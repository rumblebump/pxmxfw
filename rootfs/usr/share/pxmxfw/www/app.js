// pxmxfw web UI. The backend (pxmxfw-webui, /api) speaks plain text:
// settings are KEY=value lines, rule files are whitespace separated with
// "# comment".

const API = 'api';

class ApiError extends Error {
	constructor(message, res, text) {
		super(message);
		this.text = text;
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
	if (!res.ok) {
		const json = (res.headers.get('Content-Type') || '').startsWith('application/json');
		throw new ApiError(json ? `${res.status} ${res.statusText}` : (text.trim() || `${res.status} ${res.statusText}`), res, text);
	}
	return text;
}

// ---- security keys (WebAuthn) ----
// The server sends options with base64url strings; the browser wants
// ArrayBuffers, and its answers go back as base64url again.

const fromB64 = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)).buffer;
const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const creds = list => (list || []).map(c => ({ ...c, id: fromB64(c.id) }));

async function keyCreate(options) {
	const pk = options.publicKey;
	const cred = await navigator.credentials.create({ publicKey: {
		...pk, challenge: fromB64(pk.challenge), user: { ...pk.user, id: fromB64(pk.user.id) },
		excludeCredentials: creds(pk.excludeCredentials),
	} });
	return JSON.stringify({
		id: cred.id, rawId: toB64(cred.rawId), type: cred.type,
		response: {
			clientDataJSON: toB64(cred.response.clientDataJSON),
			attestationObject: toB64(cred.response.attestationObject),
			transports: cred.response.getTransports ? cred.response.getTransports() : [],
		},
	});
}

async function keyGet(options) {
	const pk = options.publicKey;
	const cred = await navigator.credentials.get({ publicKey: {
		...pk, challenge: fromB64(pk.challenge), allowCredentials: creds(pk.allowCredentials),
	} });
	const r = cred.response;
	return {
		id: cred.id, rawId: toB64(cred.rawId), type: cred.type,
		response: {
			clientDataJSON: toB64(r.clientDataJSON), authenticatorData: toB64(r.authenticatorData),
			signature: toB64(r.signature), userHandle: r.userHandle ? toB64(r.userHandle) : null,
		},
	};
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

// wireguard file: "tunnel NAME port=.. public=.." and "peer NAME key=.. allowed=.. ..."
function parseKVs(fields) {
	return Object.fromEntries(fields.map(f => [f.slice(0, f.indexOf('=')), f.slice(f.indexOf('=') + 1)]));
}
function parseWireguard(text) {
	const tunnels = [];
	for (const l of lines(text)) {
		const [[kind, name, ...rest], comment] = parseRule(l);
		const kv = parseKVs(rest);
		if (kind === 'tunnel') tunnels.push({ name, port: kv.port || '', public: kv.public || '', comment, peers: [], export: '' });
		const t = tunnels.find(x => x.name === name);
		if (kind === 'peer' && t) {
			t.peers.push({ name: comment, key: kv.key || '', allowed: (kv.allowed || '').replaceAll(',', ', '),
				endpoint: kv.endpoint || '', keepalive: kv.keepalive || '' });
		}
	}
	return tunnels;
}
function wireguardFile(tunnels) {
	const out = ['# WireGuard tunnels, see /usr/lib/pxmxfw/lib.sh for the format'];
	for (const t of tunnels) {
		out.push([`tunnel ${t.name}`, `port=${String(t.port).trim()}`, t.public.trim() && `public=${t.public.trim()}`]
			.filter(Boolean).join(' ') + (t.comment ? ` # ${t.comment}` : ''));
		for (const p of t.peers) {
			if (!p.key.trim() && !p.allowed.trim()) continue;
			out.push([`peer ${t.name}`, `key=${p.key.trim()}`, `allowed=${p.allowed.split(/[\s,]+/).filter(Boolean).join(',')}`,
				p.endpoint.trim() && `endpoint=${p.endpoint.trim()}`, String(p.keepalive).trim() && `keepalive=${String(p.keepalive).trim()}`]
				.filter(Boolean).join(' ') + (p.name.trim() ? ` # ${p.name.trim()}` : ''));
		}
	}
	return out.join('\n') + '\n';
}

// IPv4 helpers for suggesting peer addresses
const ip2n = ip => ip.split('.').reduce((n, o) => n * 256 + Number(o), 0);
const n2ip = n => [24, 16, 8, 0].map(s => Math.floor(n / 2 ** s) % 256).join('.');
function network(cidr) {
	const [ip, p] = cidr.split('/');
	const size = 2 ** (32 - Number(p));
	return { base: Math.floor(ip2n(ip) / size) * size, size, prefix: Number(p) };
}

const SETTINGS_ORDER = ['WAN', 'FIREWALL', 'OUTPUT_POLICY', 'IPV6', 'WEBUI_PORT', 'DNSMASQ',
	'DNS_UPSTREAM', 'DNS_DOMAIN', 'DHCP_LEASE'];

let hostId = 1;
const inNet = (ip, cidr) => {
	if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip || '') || !cidr) return false;
	const n = network(cidr);
	const x = ip2n(ip);
	return x >= n.base && x < n.base + n.size;
};

// Services of the firewall itself that rules can open per interface
const SERVICES = ['ping', 'ssh', 'dns', 'dhcp', 'webui'];
const SERVICE_LABEL = { ping: 'ping', ssh: 'SSH', dns: 'DNS', dhcp: 'DHCP', webui: 'web UI' };

// "eth2 addr=10.0.2.1/24 dhcp=a-b type=vlan link=eth1 vid=10 # c" <-> row object
function parseIface(line) {
	const [[name, ...kvs], comment] = parseRule(line);
	const kv = parseKVs(kvs);
	const mode = v => (v === undefined || v === 'proxmox') ? 'proxmox' : v === 'none' ? 'none' : 'static';
	const [dhcpStart = '', dhcpEnd = ''] = (kv.dhcp || '').split('-');
	return {
		name, comment,
		addrMode: mode(kv.addr), addr: mode(kv.addr) === 'static' ? kv.addr : '',
		addr6Mode: mode(kv.addr6), addr6: mode(kv.addr6) === 'static' ? kv.addr6 : '',
		dhcpStart, dhcpEnd,
		lease: kv.lease || '', dns: kv.dns || '',
		gwMode: kv.gateway === undefined ? '' : kv.gateway === 'none' ? 'none' : 'ip',
		gateway: kv.gateway && kv.gateway !== 'none' ? kv.gateway : '',
		routing: kv.routing === 'no' ? 'no' : 'yes', routes: (kv.routes || '').replaceAll(',', ', '),
		open: false,
		type: kv.type || '', link: kv.link || '', vid: kv.vid || '', ports: kv.ports || '',
	};
}
function ifaceLine(r, wan) {
	const f = [r.name];
	if (r.name !== wan) {
		if (r.addrMode !== 'proxmox') f.push(`addr=${r.addrMode === 'static' ? r.addr.trim() : 'none'}`);
		if (r.addr6Mode !== 'proxmox') f.push(`addr6=${r.addr6Mode === 'static' ? r.addr6.trim() : 'none'}`);
		if (r.routing === 'no') f.push('routing=no');
		if (r.dhcpStart.trim() || r.dhcpEnd.trim()) {
			f.push(`dhcp=${r.dhcpStart.trim()}-${r.dhcpEnd.trim()}`);
			if (r.lease.trim()) f.push(`lease=${r.lease.trim()}`);
			if (r.dns.trim()) f.push(`dns=${r.dns.replace(/[\s,]+/g, ',').replace(/^,|,$/g, '')}`);
			if (r.routing !== 'no') {
				if (r.gwMode === 'none') f.push('gateway=none');
				if (r.gwMode === 'ip' && r.gateway.trim()) f.push(`gateway=${r.gateway.trim()}`);
				if (list(r.routes)) f.push(`routes=${list(r.routes)}`);
			}
		}
		if (r.type === 'vlan') f.push('type=vlan', `link=${r.link}`, `vid=${String(r.vid).trim()}`);
		if (r.type === 'bridge') f.push('type=bridge', ...(r.ports ? [`ports=${r.ports}`] : []));
	}
	return f.join(' ') + (r.comment.trim() ? ` # ${r.comment.trim()}` : '');
}

// rules file lines: "input accept in=eth1 proto=tcp dport=22 # c",
// "masquerade out=eth0", "dnat in=eth0 proto=tcp dport=443 to=192.168.10.10:8443".
// In a row, proto "svc:ssh,webui" stands for service=ssh,webui.
let ruleId = 1;
const RULE_KINDS = ['input', 'forward', 'output', 'dnat', 'masquerade'];
const RULE_TITLES = { input: 'To this firewall', forward: 'Forwarding', output: 'From this firewall', dnat: 'Port forwards', masquerade: 'NAT' };
function newRule(kind, o = {}) {
	return {
		id: ruleId++, kind, action: ['input', 'output', 'forward'].includes(kind) ? 'accept' : '',
		in: '', out: '', src: '', dst: '', proto: kind === 'dnat' ? 'tcp' : '', sport: '', dport: '',
		ip: '', flags: '', toIp: '', toPort: '', comment: '', ...o,
	};
}
function parseFwRule(line) {
	const [[kind, ...rest], comment] = parseRule(line);
	const action = ['input', 'output', 'forward'].includes(kind) ? rest.shift() : '';
	const kv = parseKVs(rest);
	const [toIp = '', toPort = ''] = (kv.to || '').split(':');
	return newRule(kind, {
		action, in: kv.in || '', out: kv.out || '', src: kv.src || '', dst: kv.dst || '',
		proto: kv.service ? `svc:${kv.service}` : (kv.proto || ''), sport: kv.sport || '', dport: kv.dport || '',
		ip: kv.ip || '', flags: kv.tcpflags || '', toIp, toPort, comment,
	});
}
// a comma list without blanks
const list = v => String(v || '').split(/[\s,]+/).filter(Boolean).join(',');
function fwRuleLine(r) {
	const f = [r.kind];
	if (r.action) f.push(r.action);
	const add = (k, v) => { v = list(v); if (v) f.push(`${k}=${v}`); };
	if (r.kind !== 'output' && r.kind !== 'masquerade') add('in', r.in);
	if (r.kind !== 'input' && r.kind !== 'dnat') add('out', r.out);
	add('src', r.src);
	add('dst', r.dst);
	if (r.kind !== 'masquerade' && r.kind !== 'dnat') add('ip', r.ip);
	if (r.proto.startsWith('svc:')) add('service', r.proto.slice(4));
	else if (r.kind !== 'masquerade') {
		add('proto', r.proto);
		if (r.kind !== 'dnat') add('sport', r.sport);
		add('dport', r.dport);
		if (r.proto === 'tcp' && r.kind !== 'dnat') add('tcpflags', String(r.flags || '').replace(/\s+/g, ''));
	}
	if (r.kind === 'dnat') f.push(`to=${r.toIp.trim()}${String(r.toPort).trim() ? `:${String(r.toPort).trim()}` : ''}`);
	return f.join(' ') + (r.comment.trim() ? ` # ${r.comment.trim()}` : '');
}
const RULES_HEADER = [
	'# Firewall rules, applied in this order. Edit in the web UI or here, then',
	'# run: pxmxfw apply. Format: see /usr/lib/pxmxfw/lib.sh',
];
// A row of "Access to this firewall": input accept in=ONE service=LIST, nothing else
function isAccess(r) {
	return r.kind === 'input' && r.action === 'accept' && /^[^,\s]+$/.test(r.in) && r.proto.startsWith('svc:') &&
		!r.src.trim() && !r.dst.trim();
}

// ---- web terminal ----
// xterm.js is loaded when the terminal is first opened. The Terminal and the
// WebSocket live outside Alpine's reactive data, which would wrap them.
const term = { xterm: null, fit: null, ws: null };
function loadScript(src) {
	return new Promise((resolve, reject) => {
		const el = document.createElement('script');
		el.src = src;
		el.onload = resolve;
		el.onerror = () => reject(new Error(`could not load ${src}`));
		document.head.append(el);
	});
}
async function loadXterm() {
	if (window.Terminal && window.FitAddon) return;
	const css = document.createElement('link');
	css.rel = 'stylesheet';
	css.href = 'xterm.css';
	document.head.append(css);
	await loadScript('xterm.js');
	await loadScript('xterm-fit.js');
}

function newIface(name, o = {}) {
	return {
		name, comment: '', addrMode: 'none', addr: '', addr6Mode: 'none', addr6: '',
		dhcpStart: '', dhcpEnd: '', type: '', link: '', vid: '', ports: '',
		lease: '', dns: '', gwMode: '', gateway: '', routing: 'yes', routes: '', open: false, ...o,
	};
}

document.addEventListener('alpine:init', () => {
	Alpine.data('pxmxfw', () => ({
		tabs: [
			{ id: 'status', label: 'Status' },
			{ id: 'interfaces', label: 'Interfaces' },
			{ id: 'firewall', label: 'Firewall' },
			{ id: 'wireguard', label: 'WireGuard' },
			{ id: 'dns', label: 'DNS & DHCP' },
			{ id: 'checks', label: 'Checks' },
			{ id: 'packages', label: 'Packages' },
			{ id: 'terminal', label: 'Terminal' },
			{ id: 'security', label: 'Security' },
		],
		authed: null,
		login: { user: 'root', password: '', code: '', need: [], flow: null, error: '' },
		confirmBox: { open: false, methods: [], value: '', error: '' },
		keys: [],
		pkgs: [],
		pkgQuery: '',
		pkgResults: null,
		pkgOutput: '',
		newKeyName: '',
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
		status: { addrs: [], ifaces: [], wg: [], wgpeers: [] },
		settings: {},
		ifaces: [],
		tunnels: [],
		rules: [],
		ruleTab: 'input',
		hosts: [],
		leases: [],
		checks: [],
		ctidValue: '',
		subnetPool: '',
		SERVICES,
		SERVICE_LABEL,
		RULE_KINDS,
		RULE_TITLES,
		COL_LABEL: {
			action: 'Action', in: 'In', out: 'Out', src: 'Source', dst: 'Destination', proto: 'Protocol',
			dnatproto: 'Protocol', sport: 'Source port', dport: 'Dest. port', port: 'Port', toIp: 'To address',
			toPort: 'To port', ip: 'IP', flags: 'TCP flags', comment: 'Comment',
		},
		// the Add interface form
		adding: null,

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
			this.login.need = [];
			this.login.flow = null;
			await Promise.all([this.refresh(), this.loadConfig(), this.loadSecurity(), this.loadPkgs()]);
			try {
				const prefs = parseKV(await this.call('prefs'));
				this.ctidValue = prefs.ctid || '';
				this.subnetPool = prefs.subnet_pool || '';
			} catch (e) { /* not important */ }
		},

		async doLogin(extra = {}) {
			this.login.error = '';
			const l = this.login;
			try {
				await api('login', { body: JSON.stringify({ user: l.user, password: l.password, code: l.code, ...extra }) });
				await this.start();
			} catch (e) {
				if (!e.need) { l.error = e.message; return; }
				// the password was right; a second factor is needed
				const reply = JSON.parse(e.text);
				l.need = reply.need;
				l.flow = reply.flow ? { flow: reply.flow, options: reply.options } : null;
				if (l.flow && !extra.flow) await this.loginWithKey();
			}
		},
		async loginWithKey() {
			const f = this.login.flow;
			if (!f) return this.doLogin(); // used up: get a new challenge (which asks for the key)
			this.login.flow = null;
			try {
				const assertion = await keyGet(f.options);
				await this.doLogin({ flow: f.flow, assertion });
			} catch (e) {
				this.login.error = `Security key: ${e.message}`;
			}
		},

		async logout() {
			this.closeTerminal();
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
				await this.confirm(e.stepup.split(','));
				return await api(action, opts);
			}
		},

		confirm(methods) {
			return new Promise((resolve, reject) => {
				this.confirmBox = { open: true, methods, value: '', error: '', resolve, reject };
				if (methods.includes('webauthn')) this.confirmWithKey();
			});
		},
		async confirmWithKey() {
			const b = this.confirmBox;
			b.error = '';
			try {
				const fr = JSON.parse(await api('stepup-begin', { body: '' }));
				const assertion = await keyGet(fr.options);
				await api('stepup', { body: JSON.stringify({ flow: fr.flow, assertion }) });
				b.open = false;
				b.resolve();
			} catch (e) {
				b.error = `Security key: ${e.message}`;
			}
		},
		async submitConfirm() {
			const b = this.confirmBox;
			const body = b.methods.includes('totp') ? { code: b.value } : { password: b.value };
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
				const [me, tk, au, ks] = await Promise.all([this.call('me'), this.call('tokens'), this.call('audit'), this.call('keys')]);
				this.me = parseKV(me);
				this.keys = lines(ks).map(l => {
					const [id, name, created, used] = l.split('\t');
					return { id, name, created: date(created), used: used === '0' ? 'never' : date(used) };
				});
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
		async loadPkgs() {
			try {
				this.pkgs = lines(await this.call('pkgs')).map(l => {
					const [name, version] = l.split(' ');
					return { name, version: version === '-' ? 'not installed' : version };
				});
			} catch (e) { this.show('fail', `Could not list packages: ${e.message}`); }
		},
		async searchPkgs() {
			try {
				this.pkgResults = lines(await this.call('pkg-search', { name: this.pkgQuery.trim() })).map(l => {
					const m = l.match(/^(.+?)-([0-9][^-]*-r[0-9]+) - (.*)$/);
					return m ? { name: m[1], version: m[2], desc: m[3] } : { name: l, version: '', desc: '' };
				});
			} catch (e) { this.show('fail', e.message); }
		},
		listed(name) { return this.pkgs.some(p => p.name === name); },
		// install, remove, sync or upgrade; apk's output is shown below
		async pkgAction(action, name = '') {
			this.busy = true;
			this.pkgOutput = `Running ${action.replace('pkg-', '')} ${name}...`;
			try {
				this.pkgOutput = await this.call(action, { name, body: '' });
			} catch (e) {
				this.pkgOutput = e.message;
			}
			await this.loadPkgs();
			this.busy = false;
		},
		async addKey() {
			try {
				const fr = JSON.parse(await this.call('key-register-begin', { body: JSON.stringify({ name: this.newKeyName }) }));
				const body = await keyCreate(fr.options);
				await this.call('key-register-finish', { name: fr.flow, body });
				this.newKeyName = '';
				this.show('ok', 'Security key added. Logins and changes now ask for it.');
			} catch (e) { this.show('fail', `Could not add the key: ${e.message}`); }
			await this.loadSecurity();
		},
		async deleteKey(k) {
			try { await this.call('key-delete', { name: k.id, body: '' }); } catch (e) { this.show('fail', e.message); }
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
				kv.wg = lines(st).filter(l => l.startsWith('wg=')).map(l => {
					const [name, pub, port, state] = l.slice(3).split(' ');
					return { name, pub: pub === '-' ? '' : pub, port, state };
				});
				kv.wgpeers = lines(st).filter(l => l.startsWith('wgpeer=')).map(l => {
					const [tunnel, key, endpoint, handshake, rx, tx] = l.slice(7).split(' ');
					return { tunnel, key, endpoint, handshake: Number(handshake), rx: Number(rx), tx: Number(tx) };
				});
				kv.features = Object.fromEntries(lines(st).filter(l => l.startsWith('feature='))
					.map(l => l.slice(8).split(' ')).map(([f, v]) => [f, v === 'yes']));
				kv.ifaces = lines(st).filter(l => l.startsWith('iface=')).map(l => {
					const [name, kind, state, pve4, pve6] = l.slice(6).split(' ');
					return { name, kind, state, pve4, pve6 };
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
				const [s, ifc, rl, h, wg] = await Promise.all(['settings', 'interfaces', 'rules', 'hosts', 'wireguard'].map(n => this.call('file', { name: n })));
				this.tunnels = parseWireguard(wg);
				this.settings = { WAN: 'eth0', FIREWALL: 'rules', OUTPUT_POLICY: 'accept', ...parseKV(s) };
				this.ifaces = lines(ifc).map(parseIface);
				for (const t of this.tunnels) {
					if (!this.ifaces.some(r => r.name === t.name)) {
						this.ifaces.push(newIface(t.name, { comment: 'WireGuard', addrMode: 'none' }));
					}
				}
				this.rules = lines(rl).map(parseFwRule);
				this.hosts = lines(h).map(parseRule).map(([[ip, name, mac], comment]) => ({ id: hostId++, ip, name, mac: mac || '', comment }));
			} catch (e) {
				this.show('fail', `Could not load the configuration: ${e.message}`);
			}
		},

		// the rules in file order: grouped by kind, each kind in the order shown
		orderedRules() { return RULE_KINDS.flatMap(k => this.rules.filter(r => r.kind === k)); },
		files() {
			const settings = '# pxmxfw settings. Edit in the web UI or here, then run: pxmxfw apply\n' +
				SETTINGS_ORDER.map(k => `${k}=${(this.settings[k] || '').trim()}`).join('\n') + '\n';
			// saved in this order: interfaces are checked against the settings
			// (WAN), rules against the saved interfaces
			return {
				settings,
				wireguard: wireguardFile(this.tunnels),
				interfaces: ['# Network interfaces, see /usr/lib/pxmxfw/lib.sh for the format', ...this.ifaces.map(r => ifaceLine(r, this.wan()))].join('\n') + '\n',
				rules: [...RULES_HEADER, ...this.orderedRules().map(fwRuleLine)].join('\n') + '\n',
				hosts: ruleFile('# Hosts: IP NAME [MAC] [# comment]', this.hosts.filter(h => h.name.trim()), ['ip', 'name', 'mac']),
			};
		},
		// "line 5: dport: ..." in the rules file: say which rule that is
		ruleError(msg) {
			const rules = this.orderedRules();
			return msg.replace(/^line (\d+): /gm, (m, n) => {
				const r = rules[Number(n) - RULES_HEADER.length - 1];
				if (!r) return m;
				if (isAccess(r)) return `Access to this firewall, ${r.in}: `;
				const same = rules.filter(x => x.kind === r.kind && !isAccess(x));
				return `${RULE_TITLES[r.kind]}, rule ${same.indexOf(r) + 1}: `;
			});
		},

		async saveApply() {
			this.busy = true;
			const errors = [];
			for (const [name, body] of Object.entries(this.files())) {
				try { await this.call('save', { name, body }); } catch (e) {
					errors.push(name === 'rules' ? `Firewall rules:\n${this.ruleError(e.message)}` : `${name}: ${e.message}`);
					break;
				}
			}
			if (errors.length) {
				this.show('fail', `Not saved, please fix:\n${errors.join('\n')}`);
			} else {
				try {
					const out = await this.call('apply', { body: '' });
					this.show(/^pxmxfw: /m.test(out) ? 'warn' : 'ok', `Applied.\n${out.trim()}`);
				} catch (e) {
					this.show('fail', `Saved, but applying failed:\n${e.message}`);
				}
			}
			await Promise.all([this.refresh(), this.loadSecurity()]);
			this.busy = false;
		},

		show(kind, text) { this.message = { kind, text }; },
		yn(key, ev) { this.settings[key] = ev.target.checked ? 'yes' : 'no'; },
		ifaceOf(name) { return this.ifaces.find(r => r.name === name) || {}; },
		wgStatus(t) { return this.status.wg.find(w => w.name === t.name); },
		wgPub(t) { const w = this.wgStatus(t); return w ? w.pub : ''; },
		wgState(t) {
			const w = this.wgStatus(t);
			return !w ? 'not applied yet' : w.state === 'present' ? 'up' : 'not created (see Checks)';
		},
		handshake(t, p) {
			const s = this.status.wgpeers.find(x => x.tunnel === t.name && x.key === p.key.trim());
			if (!s || !s.handshake) return 'never';
			const ago = Math.max(0, Math.round(Date.now() / 1000 - s.handshake));
			return ago < 120 ? `${ago}s ago` : ago < 7200 ? `${Math.round(ago / 60)}m ago` : `${Math.round(ago / 3600)}h ago`;
		},
		freeName(prefix) {
			let i = 0;
			while (this.ifaces.some(r => r.name === `${prefix}${i}`)) i++;
			return `${prefix}${i}`;
		},
		async proposeAddr(name) {
			try { return (await this.call('propose-subnet', { name })).trim(); } catch (e) { this.show('warn', e.message); return ''; }
		},
		async addTunnel() {
			const name = this.freeName('wg');
			const addr = await this.proposeAddr(name);
			this.tunnels.push({ name, port: String(51820 + Number(name.slice(2))), public: '', comment: '', peers: [], export: '' });
			this.ifaces.push(newIface(name, { comment: 'WireGuard', addrMode: addr ? 'static' : 'none', addr }));
			this.defaultRules(name);
		},

		// ---- Add interface (VLAN, bridge, WireGuard tunnel) ----
		feature(f) { return !!(this.status.features || {})[f]; },
		// NICs a VLAN can sit on: anything listed except bridge ports
		vlanParents() {
			return this.ifaces.filter(r => r.type !== 'vlan' && !this.bridgeOf(r.name) && !this.tunnels.some(t => t.name === r.name)).map(r => r.name);
		},
		// NICs free to join a new bridge: not WAN, not a tunnel, in no bridge,
		// and without an address pxmxfw sets
		bridgeCandidates() {
			return this.ifaces.filter(r => r.name !== this.wan() && r.type !== 'bridge' && !this.bridgeOf(r.name) &&
				!this.tunnels.some(t => t.name === r.name) && r.addrMode !== 'static' && !r.dhcpStart).map(r => r.name);
		},
		bridgeOf(name) { return this.ifaces.find(r => r.type === 'bridge' && r.ports.split(',').includes(name)); },
		async startAdd() {
			const kind = this.feature('vlan') ? 'vlan' : this.feature('bridge') ? 'bridge' : 'wireguard';
			const link = (this.ifaces.find(r => r.name !== this.wan()) || this.ifaces[0] || {}).name || 'eth1';
			this.adding = { kind, link, vid: '10', name: '', ports: [], addr: '', dhcp: false, comment: '' };
			await this.addKind();
		},
		async addKind() {
			const a = this.adding;
			a.name = a.kind === 'vlan' ? `${a.link}.${a.vid}`.slice(0, 15) : this.freeName(a.kind === 'bridge' ? 'br' : 'wg');
			a.addr = await this.proposeAddr(a.name);
		},
		addVlanName() { const a = this.adding; a.name = `${a.link}.${a.vid}`.slice(0, 15); },
		async finishAdd() {
			const a = this.adding;
			if (a.kind === 'wireguard') { this.adding = null; await this.addTunnel(); this.tab = 'wireguard'; return; }
			if (!/^[A-Za-z0-9_.-]{1,15}$/.test(a.name) || this.ifaces.some(r => r.name === a.name)) {
				this.show('warn', 'Pick an unused name of at most 15 letters, digits, dots, dashes or underscores.'); return;
			}
			if (a.kind === 'vlan' && !(Number(a.vid) >= 1 && Number(a.vid) <= 4094)) { this.show('warn', 'The VLAN ID is 1 to 4094.'); return; }
			const r = newIface(a.name, {
				comment: a.comment, addrMode: a.addr ? 'static' : 'none', addr: a.addr,
				type: a.kind, link: a.kind === 'vlan' ? a.link : '', vid: a.kind === 'vlan' ? a.vid : '',
				ports: a.kind === 'bridge' ? a.ports.join(',') : '',
			});
			if (a.dhcp && a.addr) {
				const n = network(a.addr);
				r.dhcpStart = n2ip(n.base + 100); r.dhcpEnd = n2ip(n.base + 200);
			}
			// bridge ports carry no address of their own; their rules move to the bridge
			for (const p of a.ports) {
				Object.assign(this.ifaceOf(p), { addrMode: 'none', addr6Mode: 'none' });
				this.renameInRules(p, r.name);
			}
			this.ifaces.push(r);
			this.defaultRules(r.name);
			this.adding = null;
			this.show('ok', `${r.name} added. Click Save and apply to create it.`);
		},
		// ---- per-interface DHCP and DNS ----
		// interfaces that can run DHCP and have rules: not the WAN, not a bridge port
		inside(r) { return r.name !== this.wan() && !this.bridgeOf(r.name); },
		// the interface's IPv4 subnet: its static address, else what it has now
		subnetOf(r) {
			const c = r.addrMode === 'static' && /\/\d+$/.test(r.addr) ? r.addr
				: (this.status.addrs.find(a => a[0] === r.name && !a[1].includes(':')) || [])[1];
			if (!c) return '';
			const n = network(c);
			return `${n2ip(n.base)}/${n.prefix}`;
		},
		rangeHint(r, host) { const c = this.subnetOf(r); return c ? n2ip(network(c).base + host) : ''; },
		dhcpSummary(r) {
			if (!(r.dhcpStart || r.dhcpEnd)) return 'off';
			const tail = ip => (ip || '').split('.').pop();
			return `.${tail(r.dhcpStart)} to .${tail(r.dhcpEnd)}`;
		},
		toggleDhcp(r, ev) {
			if (ev.target.checked) {
				r.dhcpStart = this.rangeHint(r, 100); r.dhcpEnd = this.rangeHint(r, 200);
				if (!r.dhcpStart) { ev.target.checked = false; this.show('warn', `Give ${r.name} an IPv4 address first.`); }
			} else {
				r.dhcpStart = r.dhcpEnd = '';
			}
		},
		hostsIn(r) { const c = this.subnetOf(r); return c ? this.hosts.filter(h => inNet(h.ip, c)) : []; },
		otherHosts() {
			const nets = this.ifaces.filter(r => this.inside(r)).map(r => this.subnetOf(r)).filter(Boolean);
			return this.hosts.filter(h => !nets.some(c => inNet(h.ip, c)));
		},
		leasesIn(r) { const c = this.subnetOf(r); return c ? this.leases.filter(l => inNet(l[2], c)) : []; },
		addHost(r) {
			const c = r && this.subnetOf(r);
			// a new row starts in the subnet, so it shows up under this interface
			let ip = '';
			if (c) {
				const n = network(c);
				const used = new Set(this.hosts.map(h => h.ip));
				for (let x = n.base + 10; x < n.base + n.size - 1 && !ip; x++) if (!used.has(n2ip(x))) ip = n2ip(x);
			}
			this.hosts.push({ id: hostId++, ip, name: '', mac: '', comment: '' });
		},
		removeHost(h) { this.hosts = this.hosts.filter(x => x !== h); },

		removeIface(r) {
			this.ifaces = this.ifaces.filter(x => x !== r);
			this.renameInRules(r.name, '');
		},

		// ---- firewall rules ----
		wan() { return this.settings.WAN || 'eth0'; },
		// NICs from Proxmox that can be the WAN
		wanChoices() { return this.ifaces.filter(r => !r.type && !this.tunnels.some(t => t.name === r.name)).map(r => r.name); },
		// interfaces rules can name (bridge ports pass traffic as their bridge)
		ruleIfaces() { return this.ifaces.filter(r => !this.bridgeOf(r.name)).map(r => r.name); },
		rulesOf(kind) { return this.rules.filter(r => r.kind === kind && !isAccess(r)); },
		// the columns of the rule table shown
		cols() {
			return {
				input: ['action', 'in', 'ip', 'src', 'dst', 'proto', 'sport', 'dport', 'flags', 'comment'],
				forward: ['action', 'in', 'out', 'ip', 'src', 'dst', 'proto', 'sport', 'dport', 'flags', 'comment'],
				output: ['action', 'out', 'ip', 'dst', 'proto', 'sport', 'dport', 'flags', 'comment'],
				dnat: ['in', 'dnatproto', 'port', 'toIp', 'toPort', 'src', 'dst', 'comment'],
				masquerade: ['out', 'src', 'dst', 'comment'],
			}[this.ruleTab];
		},
		ruleHelp() {
			return {
				input: 'Traffic to the firewall itself, besides the services above. Anything no rule accepts is dropped.',
				forward: 'Traffic the firewall routes from one interface to another. Anything no rule accepts is dropped; replies to accepted connections and port forwards always pass.',
				output: `Traffic the firewall itself sends. Anything no rule matches is ${this.settings.OUTPUT_POLICY === 'drop' ? 'dropped' : 'accepted'} (see General below).`,
				dnat: 'Connections to a port on an interface go to a machine behind the firewall. Destination limits it to one of the firewall\'s addresses. They pass without a forwarding rule. IPv4 only.',
				masquerade: 'Traffic leaving an interface gets that interface\'s address (NAT), so machines behind the firewall can reach the internet. IPv4 only.',
			}[this.ruleTab];
		},
		addRule(kind) {
			const o = kind === 'dnat' ? { in: this.wan() } : kind === 'masquerade' ? { out: this.wan() } : {};
			this.rules.push(newRule(kind, o));
		},
		removeRule(r) { this.rules = this.rules.filter(x => x !== r); },
		// move a rule up or down among the rules of its table
		moveRule(r, dir) {
			const same = this.rulesOf(r.kind);
			const other = same[same.indexOf(r) + dir];
			if (!other) return;
			const i = this.rules.indexOf(r), j = this.rules.indexOf(other);
			[this.rules[i], this.rules[j]] = [other, r];
		},
		// protocol choices of a rule, keeping an unusual service list it already has
		protoOptions(r) {
			const o = [['', 'any'], ['tcp', 'TCP'], ['udp', 'UDP'], ['tcp,udp', 'TCP and UDP'], ['icmp', 'ICMP'],
				['icmpv6', 'ICMPv6'], ['gre', 'GRE'], ['esp', 'ESP (IPsec)'], ['ah', 'AH (IPsec)'], ['ipip', 'IP in IP']];
			if (r.kind === 'input') {
				for (const s of SERVICES) o.push([`svc:${s}`, `service: ${SERVICE_LABEL[s]}`]);
				if (r.proto.startsWith('svc:') && !o.some(x => x[0] === r.proto)) o.push([r.proto, `service: ${r.proto.slice(4)}`]);
			}
			return o;
		},
		ports(r) { return ['tcp', 'udp', 'tcp,udp'].includes(r.proto); },
		// a plain-language line under each rule
		describe(r) {
			const any = (v, all) => list(v) ? list(v).replaceAll(',', ', ') : all;
			const what = r.proto.startsWith('svc:') ? r.proto.slice(4).split(',').map(s => SERVICE_LABEL[s] || s).join(', ')
				: !r.proto ? 'all traffic' : `${r.proto.replace(',', '/').toUpperCase()}${list(r.dport) ? ` to port ${any(r.dport)}` : ''}`;
			const fam = r.ip ? `IPv${r.ip} ` : '';
			const flags = r.proto === 'tcp' && r.flags ? ` with flags ${r.flags}` : '';
			const from = `${any(r.src, 'anywhere')}${r.in ? ` on ${any(r.in)}` : ''}`;
			switch (r.kind) {
				case 'input': return `${r.action} ${fam}${what}${flags} from ${from} to this firewall`;
				case 'output': return `${r.action} ${fam}${what}${flags} from this firewall to ${any(r.dst, 'anywhere')}${r.out ? ` via ${any(r.out)}` : ''}`;
				case 'forward': return `${r.action} ${fam}${what}${flags} from ${from} to ${any(r.dst, 'anywhere')}${r.out ? ` via ${any(r.out)}` : ''}`;
				case 'dnat': return `${(r.proto || '').toUpperCase()} port ${r.dport || '?'} on ${any(r.in, '?')} goes to ${r.toIp || '?'}${r.toPort ? `:${r.toPort}` : ''}`;
				case 'masquerade': return `traffic from ${any(r.src, 'anywhere')} leaving ${any(r.out, '?')} gets its address`;
			}
			return '';
		},
		// Access to this firewall: which services each interface reaches
		access(name) { return this.rules.find(r => isAccess(r) && r.in === name); },
		accessHas(name, svc) {
			const r = this.access(name);
			return !!r && r.proto.slice(4).split(',').includes(svc);
		},
		// DHCP ranges let DHCP and DNS in on their interface anyway
		accessImplied(name, svc) { return (svc === 'dhcp' || svc === 'dns') && !!this.ifaceOf(name).dhcpStart; },
		toggleAccess(name, svc, ev) {
			let r = this.access(name);
			const have = r ? r.proto.slice(4).split(',') : [];
			const want = SERVICES.filter(s => s === svc ? ev.target.checked : have.includes(s));
			if (!r && want.length) {
				// after the other input rules of the table, so earlier drops still win
				r = newRule('input', { in: name });
				this.rules.push(r);
			}
			if (r && want.length) r.proto = `svc:${want.join(',')}`;
			if (r && !want.length) this.removeRule(r);
			if (svc === 'webui' && !ev.target.checked && !this.webuiReachable())
				this.show('warn', 'No rule lets an interface reach the web UI now. After applying it can only be reached from inside the container.');
		},
		// some rule accepts the web UI, from interfaces in names (all when empty)
		webuiReachable(names) {
			return this.rules.some(r => r.kind === 'input' && r.action === 'accept' &&
				(r.proto.split(':')[1] || '').split(',').includes('webui') &&
				(!names || !r.in || list(r.in).split(',').some(i => names.includes(i))));
		},
		// Routing off: nothing is routed from or to R, so it leaves the forwarding
		// and NAT rules. Routing on: it gets a rule to reach WAN if no rule routes it.
		setRouting(r, v) {
			r.routing = v;
			const named = x => list(`${x.in},${x.out}`).split(',').includes(r.name);
			if (v === 'no') {
				const before = this.rules.length;
				this.rules = this.rules.filter(x => !((x.kind === 'forward' || x.kind === 'masquerade') && named(x)) ||
					!this.dropIface(x, r.name));
				if (this.rules.length !== before) this.show('ok', `${r.name} is no longer routed; its forwarding rules were removed.`);
			} else if (!this.rules.some(x => x.kind === 'forward' && named(x))) {
				this.rules.push(newRule('forward', { in: r.name, out: this.wan(), comment: `${r.name} to WAN` }));
				this.show('ok', `${r.name} is routed and got a rule to reach WAN; change it under Firewall.`);
			}
		},
		// take NAME out of rule X; true when X names nothing else there (so it goes)
		dropIface(x, name) {
			const fix = v => list(v).split(',').filter(n => n && n !== name).join(',');
			const inHad = list(x.in).split(',').includes(name), outHad = list(x.out).split(',').includes(name);
			x.in = fix(x.in); x.out = fix(x.out);
			return (inHad && !x.in) || (outHad && !x.out);
		},
		// subnets of the other routed interfaces, for routes handed out by DHCP
		routedNets(r) {
			return [...new Set(this.ifaces.filter(x => x !== r && x.routing !== 'no' && this.inside(x)).map(x => this.subnetOf(x)).filter(Boolean))];
		},
		// a new interface reaches WAN and answers ping, like the LAN at first boot
		defaultRules(name) {
			this.rules.push(newRule('input', { in: name, proto: 'svc:ping' }));
			this.rules.push(newRule('forward', { in: name, out: this.wan(), comment: `${name} to WAN` }));
		},
		// NAME becomes TO in every rule. With TO empty, NAME leaves the rules, and
		// a rule that named only NAME as in= or out= goes (it would match any)
		renameInRules(name, to) {
			const fix = v => [...new Set(list(v).split(',').filter(Boolean).map(x => x === name ? to : x).filter(Boolean))].join(',');
			this.rules = this.rules.filter(r => {
				const inHad = list(r.in).split(',').includes(name), outHad = list(r.out).split(',').includes(name);
				r.in = fix(r.in); r.out = fix(r.out);
				return !((inHad && !r.in) || (outHad && !r.out));
			});
		},

		termOpen: false,
		termNote: '',
		async openTerminal() {
			if (term.ws) return;
			this.termNote = '';
			try {
				// asks for a fresh confirmation first, like a change
				await this.call('term', { body: '' });
				await loadXterm();
			} catch (e) {
				this.termNote = e.message;
				return;
			}
			const box = document.getElementById('term');
			if (!term.xterm) {
				term.xterm = new window.Terminal({ cursorBlink: true, fontSize: 14, scrollback: 5000 });
				term.fit = new window.FitAddon.FitAddon();
				term.xterm.loadAddon(term.fit);
				term.xterm.open(box);
				term.xterm.onData(d => term.ws && term.ws.readyState === 1 && term.ws.send(new TextEncoder().encode(d)));
				term.xterm.onResize(({ cols, rows }) => term.ws && term.ws.readyState === 1 && term.ws.send(JSON.stringify({ cols, rows })));
				window.addEventListener('resize', () => this.tab === 'terminal' && term.fit.fit());
			} else {
				term.xterm.reset();
			}
			const ws = new WebSocket(`wss://${location.host}/term`);
			ws.binaryType = 'arraybuffer';
			term.ws = ws;
			this.termOpen = true;
			ws.onopen = () => {
				term.fit.fit();
				ws.send(JSON.stringify({ cols: term.xterm.cols, rows: term.xterm.rows }));
				term.xterm.focus();
			};
			ws.onmessage = ev => term.xterm.write(new Uint8Array(ev.data));
			ws.onclose = ev => {
				term.xterm.write(`\r\n\x1b[2m[terminal closed${ev.reason ? `: ${ev.reason}` : ''}]\x1b[0m\r\n`);
				term.ws = null;
				this.termOpen = false;
			};
		},
		closeTerminal() { if (term.ws) term.ws.close(1000, 'closed'); },
		showTerminal() { this.$nextTick(() => term.fit && term.fit.fit()); },

		async savePool() {
			try { await this.call('pref', { name: 'subnet_pool', body: this.subnetPool.trim() }); } catch (e) { this.show('fail', e.message); }
		},
		removeTunnel(ti) {
			const name = this.tunnels[ti].name;
			this.tunnels.splice(ti, 1);
			this.ifaces = this.ifaces.filter(r => r.name !== name);
		},
		// Suggest the next free address in the tunnel subnet for a new peer
		nextPeerAddr(t) {
			const own = this.ifaceOf(t.name).addr || '';
			if (!/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(own)) return '';
			const net = network(own);
			const used = new Set([ip2n(own.split('/')[0])]);
			for (const p of t.peers) for (const a of p.allowed.split(/[\s,]+/)) if (a.endsWith('/32')) used.add(ip2n(a.slice(0, -3)));
			for (let n = net.base + 2; n < net.base + net.size - 1; n++) if (!used.has(n)) return n2ip(n);
			return '';
		},
		async newPeer(t) {
			const pub = this.wgPub(t);
			if (!pub) { this.show('warn', `Click Save and apply first, so ${t.name} gets its keys.`); return; }
			if (!t.public.trim()) { this.show('warn', `Fill in the public endpoint of ${t.name} first, so the peer knows where to connect.`); return; }
			try {
				const kp = parseKV(await this.call('wgkeypair', { body: '' }));
				const addr = this.nextPeerAddr(t);
				const own = this.ifaceOf(t.name).addr;
				const net = network(own);
				// the tunnel subnet and the lans behind this firewall
				const lans = [...new Set(this.ifaces.filter(r => this.inside(r) && r.name !== t.name)
					.flatMap(r => {
						const live = this.status.addrs.filter(a => a[0] === r.name && !a[1].includes(':')).map(a => a[1]);
						return live.length ? live : (r.addrMode === 'static' && r.addr ? [r.addr] : []);
					})
					.map(c => { const n = network(c); return `${n2ip(n.base)}/${n.prefix}`; }))];
				t.peers.push({ name: `peer${t.peers.length + 1}`, key: kp.public, allowed: addr ? `${addr}/32` : '', endpoint: '', keepalive: '' });
				t.export = [
					'[Interface]',
					`PrivateKey = ${kp.private}`,
					addr ? `Address = ${addr}/${net.prefix}` : '# Address = <a free address in the tunnel subnet>',
					'',
					'[Peer]',
					`PublicKey = ${pub}`,
					`Endpoint = ${t.public.trim()}`,
					`AllowedIPs = ${[`${n2ip(net.base)}/${net.prefix}`, ...lans].join(', ')}`,
					'PersistentKeepalive = 25',
				].join('\n');
				this.show('ok', 'Peer added. Click Save and apply to activate it.');
			} catch (e) {
				this.show('fail', `Could not create keys: ${e.message}`);
			}
		},
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
