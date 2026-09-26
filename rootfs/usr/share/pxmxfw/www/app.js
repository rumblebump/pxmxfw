// pxmxfw web UI. The backend (pxmxfw-webui, /api) speaks plain text:
// settings are KEY=value lines, rule files are whitespace separated with
// "# comment".

const API = 'api';

class ApiError extends Error {
	constructor(message, res) {
		super(message);
		this.status = res.status;
		this.stepup = res.headers.get('X-Pxmxfw-Stepup');
		this.need = res.headers.get('X-Pxmxfw-Need');
	}
}

async function api(action, { name, body } = {}) {
	const q = new URLSearchParams({ action });
	if (name) q.set('name', name);
	const opts = body === undefined ? {} : {
		method: 'POST',
		headers: { 'X-Pxmxfw': '1', 'Content-Type': 'text/plain' },
		body,
	};
	const res = await fetch(`${API}?${q}`, opts);
	const text = await res.text();
	if (!res.ok) throw new ApiError(text.trim() || `${res.status} ${res.statusText}`, res);
	return text;
}

function date(unix) {
	return new Date(Number(unix) * 1000).toLocaleString();
}

function lines(text) {
	return text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
}

function parseKV(text) {
	const out = {};
	for (const l of lines(text)) {
		const i = l.indexOf('=');
		if (i > 0) out[l.slice(0, i)] = l.slice(i + 1).replace(/\s+#.*$/, '').trim();
	}
	return out;
}

// Split "a b c # comment" into [[a, b, c], comment]
function parseRule(line) {
	const i = line.indexOf('#');
	const comment = i >= 0 ? line.slice(i + 1).trim() : '';
	const fields = (i >= 0 ? line.slice(0, i) : line).trim().split(/\s+/);
	return [fields, comment];
}

function ruleFile(header, rows, fields) {
	const body = rows
		.filter(r => fields.some(f => String(r[f] || '').trim()))
		.map(r => {
			const parts = fields.map(f => String(r[f] || '').trim()).filter(Boolean);
			return parts.join(' ') + (r.comment.trim() ? ` # ${r.comment.trim()}` : '');
		});
	return [header, ...body].join('\n') + '\n';
}

const SETTINGS_ORDER = ['NAT', 'WAN_PING', 'IPV6', 'WEBUI_PORT', 'WEBUI_WAN', 'DNSMASQ',
	'DNS_UPSTREAM', 'DNS_DOMAIN', 'DHCP_LEASE'];

// "eth2 role=lan addr=10.0.2.1/24 dhcp=a-b # c" <-> row object
function parseIface(line) {
	const [[name, ...kvs], comment] = parseRule(line);
	const kv = Object.fromEntries(kvs.map(f => [f.slice(0, f.indexOf('=')), f.slice(f.indexOf('=') + 1)]));
	const mode = v => (v === undefined || v === 'proxmox') ? 'proxmox' : v === 'none' ? 'none' : 'static';
	const [dhcpStart = '', dhcpEnd = ''] = (kv.dhcp || '').split('-');
	return {
		name, role: kv.role || 'off', comment,
		addrMode: mode(kv.addr), addr: mode(kv.addr) === 'static' ? kv.addr : '',
		addr6Mode: mode(kv.addr6), addr6: mode(kv.addr6) === 'static' ? kv.addr6 : '',
		dhcpStart, dhcpEnd,
	};
}
function ifaceLine(r) {
	const f = [r.name, `role=${r.role}`];
	if (r.role !== 'wan') {
		if (r.addrMode !== 'proxmox') f.push(`addr=${r.addrMode === 'static' ? r.addr.trim() : 'none'}`);
		if (r.addr6Mode !== 'proxmox') f.push(`addr6=${r.addr6Mode === 'static' ? r.addr6.trim() : 'none'}`);
		if ((r.role === 'lan' || r.role === 'isolated') && (r.dhcpStart.trim() || r.dhcpEnd.trim()))
			f.push(`dhcp=${r.dhcpStart.trim()}-${r.dhcpEnd.trim()}`);
	}
	return f.join(' ') + (r.comment.trim() ? ` # ${r.comment.trim()}` : '');
}

document.addEventListener('alpine:init', () => {
	Alpine.data('pxmxfw', () => ({
		tabs: [
			{ id: 'status', label: 'Status' },
			{ id: 'interfaces', label: 'Interfaces' },
			{ id: 'firewall', label: 'Firewall' },
			{ id: 'dns', label: 'DNS & DHCP' },
			{ id: 'checks', label: 'Checks' },
			{ id: 'security', label: 'Security' },
		],
		authed: null,
		login: { user: 'root', password: '', code: '', needCode: false, error: '' },
		confirmBox: { open: false, method: '', value: '', error: '' },
		me: {},
		totpSetup: null,
		totpCode: '',
		tokens: [],
		newToken: { name: '', scope: 'write', days: 365 },
		createdToken: '',
		audit: [],
		tab: 'status',
		busy: false,
		message: { text: '', kind: '' },
		status: { addrs: [], ifaces: [] },
		settings: {},
		ifaces: [],
		services: [],
		forwards: [],
		hosts: [],
		leases: [],
		checks: [],
		ctidValue: '',

		async init() {
			try {
				await api('me');
				await this.start();
			} catch (e) {
				this.authed = false;
			}
		},

		async start() {
			this.authed = true;
			this.login.password = this.login.code = this.login.error = '';
			this.login.needCode = false;
			await Promise.all([this.refresh(), this.loadConfig(), this.loadSecurity()]);
			try { this.ctidValue = parseKV(await this.call('prefs')).ctid || ''; } catch (e) { /* not important */ }
		},

		async doLogin() {
			this.login.error = '';
			try {
				await api('login', { body: JSON.stringify({ user: this.login.user, password: this.login.password, code: this.login.code }) });
				await this.start();
			} catch (e) {
				if (e.need === 'totp') this.login.needCode = true;
				else this.login.error = e.message;
			}
		},

		async logout() {
			try { await api('logout', { body: '' }); } catch (e) { /* session already gone */ }
			this.authed = false;
		},

		// call() is api() plus the login and confirm prompts: an expired session
		// shows the login form, and a change that needs confirming asks for the
		// TOTP code (or password) and is then retried once.
		async call(action, opts = {}) {
			try {
				return await api(action, opts);
			} catch (e) {
				if (e.status === 401) this.authed = false;
				if (e.status !== 403 || !e.stepup) throw e;
				await this.confirm(e.stepup);
				return await api(action, opts);
			}
		},

		confirm(method) {
			return new Promise((resolve, reject) => {
				this.confirmBox = { open: true, method, value: '', error: '', resolve, reject };
			});
		},
		async submitConfirm() {
			const b = this.confirmBox;
			const body = b.method === 'totp' ? { code: b.value } : { password: b.value };
			try {
				await api('stepup', { body: JSON.stringify(body) });
				b.open = false;
				b.resolve();
			} catch (e) {
				b.error = e.message;
				b.value = '';
			}
		},
		cancelConfirm() {
			this.confirmBox.open = false;
			this.confirmBox.reject(new Error('Not confirmed.'));
		},

		async loadSecurity() {
			try {
				const [me, tk, au] = await Promise.all([this.call('me'), this.call('tokens'), this.call('audit')]);
				this.me = parseKV(me);
				this.tokens = lines(tk).map(l => {
					const [id, name, scope, created, expires, used] = l.split('\t');
					return { id, name, scope, created: date(created), expires: date(expires), used: used === '0' ? 'never' : date(used) };
				});
				this.audit = lines(au).map(l => {
					const [ts, user, action, detail] = l.split('\t');
					return { ts: date(ts), user, action, detail };
				});
			} catch (e) {
				this.show('fail', `Could not load the security settings: ${e.message}`);
			}
		},

		async startTotp() {
			try {
				this.totpSetup = parseKV(await this.call('totp-setup', { body: '' }));
				this.totpCode = '';
			} catch (e) { this.show('fail', e.message); }
		},
		async enableTotp() {
			try {
				await this.call('totp-enable', { body: JSON.stringify({ code: this.totpCode }) });
				this.totpSetup = null;
				this.show('ok', 'Two-factor login is on. Changes are now confirmed with a code from your app.');
			} catch (e) { this.show('fail', e.message); }
			await this.loadSecurity();
		},
		async disableTotp() {
			try {
				await this.call('totp-disable', { body: '' });
				this.show('ok', 'Two-factor login is off.');
			} catch (e) { this.show('fail', e.message); }
			await this.loadSecurity();
		},
		async createToken() {
			try {
				this.createdToken = (await this.call('token-create', { body: JSON.stringify({ ...this.newToken, days: Number(this.newToken.days) }) })).trim();
				this.newToken.name = '';
			} catch (e) { this.show('fail', e.message); }
			await this.loadSecurity();
		},
		async deleteToken(t) {
			try { await this.call('token-delete', { name: t.id, body: '' }); } catch (e) { this.show('fail', e.message); }
			await this.loadSecurity();
		},

		async refresh() {
			try {
				const [st, ck, ls] = await Promise.all([this.call('status'), this.call('check'), this.call('leases')]);
				const kv = parseKV(st);
				kv.addrs = lines(st).filter(l => l.startsWith('addr=')).map(l => l.slice(5).split(' '));
				kv.ifaces = lines(st).filter(l => l.startsWith('iface=')).map(l => {
					const [name, role, state, pve4, pve6] = l.slice(6).split(' ');
					return { name, role, state, pve4, pve6 };
				});
				this.status = kv;
				this.checks = lines(ck).map(l => {
					const [status, id, title, detail, hint] = l.split('\t');
					return { status, id, title, detail, hint: hint || '' };
				});
				this.leases = lines(ls).map(l => l.split(' '))
					.map(([exp, mac, ip, name]) => [exp === '0' ? 'never' : new Date(exp * 1000).toLocaleString(), mac, ip, name === '*' ? '' : name]);
			} catch (e) {
				this.show('fail', `Could not load status: ${e.message}`);
			}
		},

		async loadConfig() {
			try {
				const [s, ifc, sv, fw, h] = await Promise.all(['settings', 'interfaces', 'services', 'forwards', 'hosts'].map(n => this.call('file', { name: n })));
				this.settings = parseKV(s);
				this.ifaces = lines(ifc).map(parseIface);
				this.services = lines(sv).map(parseRule).map(([[proto, port], comment]) => ({ proto, port, comment }));
				this.forwards = lines(fw).map(parseRule).map(([[proto, wanport, lanip, lanport], comment]) => ({ proto, wanport, lanip, lanport, comment }));
				this.hosts = lines(h).map(parseRule).map(([[ip, name, mac], comment]) => ({ ip, name, mac: mac || '', comment }));
			} catch (e) {
				this.show('fail', `Could not load the configuration: ${e.message}`);
			}
		},

		files() {
			const settings = '# pxmxfw settings. Edit in the web UI or here, then run: pxmxfw apply\n' +
				SETTINGS_ORDER.map(k => `${k}=${(this.settings[k] || '').trim()}`).join('\n') + '\n';
			return {
				settings,
				interfaces: ['# Network interfaces, see /usr/lib/pxmxfw/lib.sh for the format', ...this.ifaces.map(ifaceLine)].join('\n') + '\n',
				services: ruleFile('# Open on WAN: tcp|udp PORT[-PORT] [# comment]', this.services, ['proto', 'port']),
				forwards: ruleFile('# Port forwards: tcp|udp WANPORT LANIP LANPORT [# comment]', this.forwards, ['proto', 'wanport', 'lanip', 'lanport']),
				hosts: ruleFile('# Hosts: IP NAME [MAC] [# comment]', this.hosts, ['ip', 'name', 'mac']),
			};
		},

		async saveApply() {
			this.busy = true;
			const errors = [];
			for (const [name, body] of Object.entries(this.files())) {
				try { await this.call('save', { name, body }); } catch (e) { errors.push(`${name}: ${e.message}`); break; }
			}
			if (errors.length) {
				this.show('fail', `Not saved, please fix:\n${errors.join('\n')}`);
			} else {
				try {
					const out = await this.call('apply', { body: '' });
					this.show('ok', `Applied.\n${out.trim()}`);
				} catch (e) {
					this.show('fail', `Saved, but applying failed:\n${e.message}`);
				}
			}
			await Promise.all([this.refresh(), this.loadSecurity()]);
			this.busy = false;
		},

		show(kind, text) { this.message = { kind, text }; },
		yn(key, ev) { this.settings[key] = ev.target.checked ? 'yes' : 'no'; },
		ipv6() { return this.settings.IPV6 === 'yes'; },
		addrsOf(name) { return this.status.addrs.filter(a => a[0] === name).map(a => a[1]).join(', '); },
		nowOf(r) {
			const st = this.status.ifaces.find(i => i.name === r.name);
			if (st && st.state === 'missing') return 'not in this container';
			return this.addrsOf(r.name) || 'no address';
		},
		uptime() {
			const s = Number(this.status.uptime || 0);
			const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
			return d ? `${d}d ${h}h` : `${h}h ${m}m`;
		},

		get failedChecks() { return this.checks.filter(c => c.status === 'fail'); },
		get missingModules() {
			const mods = this.checks
				.filter(c => c.status !== 'ok' && c.hint.startsWith('modules:'))
				.flatMap(c => c.hint.slice(8).split(' '));
			return [...new Set(mods)].filter(Boolean);
		},
		hintText(c) {
			if (c.hint.startsWith('modules:')) return `On the Proxmox host: modprobe -a ${c.hint.slice(8)} (see below to keep it loaded)`;
			return this.ctid(c.hint);
		},
		ctid(text) { return text.replaceAll('CTID', this.ctidValue.trim() || 'CTID'); },
		async saveCtid() { try { await this.call('pref', { name: 'ctid', body: this.ctidValue.trim() }); } catch (e) { /* not important */ } },
		hostCommands() {
			const m = this.missingModules.join(' ');
			return this.ctid([
				`modprobe -a ${m}`,
				`printf '%s\\n' ${m} >> /etc/modules-load.d/pxmxfw.conf`,
				'pct reboot CTID',
			].join('\n'));
		},
		async copy(text) {
			try { await navigator.clipboard.writeText(text); this.show('ok', 'Copied.'); } catch (e) { /* insecure context */ }
		},
	}));
});
