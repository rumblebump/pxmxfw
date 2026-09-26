// pxmxfw web UI. The backend (cgi-bin/api) speaks plain text: settings are
// KEY=value lines, rule files are whitespace separated with "# comment".

const API = 'cgi-bin/api';

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
	if (!res.ok) throw new Error(text.trim() || `${res.status} ${res.statusText}`);
	return text;
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
			{ id: 'wireguard', label: 'WireGuard' },
			{ id: 'dns', label: 'DNS & DHCP' },
			{ id: 'checks', label: 'Checks' },
		],
		tab: 'status',
		busy: false,
		message: { text: '', kind: '' },
		status: { addrs: [], ifaces: [], wg: [], wgpeers: [] },
		settings: {},
		ifaces: [],
		tunnels: [],
		services: [],
		forwards: [],
		hosts: [],
		leases: [],
		checks: [],
		ctidValue: '',

		async init() {
			try { this.ctidValue = localStorage.getItem('pxmxfw.ctid') || ''; } catch (e) { /* no storage */ }
			await this.refresh();
			await this.loadConfig();
		},

		async refresh() {
			try {
				const [st, ck, ls] = await Promise.all([api('status'), api('check'), api('leases')]);
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
				const [s, ifc, sv, fw, h, wg] = await Promise.all(['settings', 'interfaces', 'services', 'forwards', 'hosts', 'wireguard'].map(n => api('file', { name: n })));
				this.tunnels = parseWireguard(wg);
				this.settings = parseKV(s);
				this.ifaces = lines(ifc).map(parseIface);
				for (const t of this.tunnels) {
					if (!this.ifaces.some(r => r.name === t.name)) {
						this.ifaces.push({ name: t.name, role: 'lan', comment: 'WireGuard', addrMode: 'none', addr: '',
							addr6Mode: 'none', addr6: '', dhcpStart: '', dhcpEnd: '' });
					}
				}
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
				wireguard: wireguardFile(this.tunnels),
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
				try { await api('save', { name, body }); } catch (e) { errors.push(`${name}: ${e.message}`); break; }
			}
			if (errors.length) {
				this.show('fail', `Not saved, please fix:\n${errors.join('\n')}`);
			} else {
				try {
					const out = await api('apply', { body: '' });
					this.show(/^pxmxfw: /m.test(out) ? 'warn' : 'ok', `Applied.\n${out.trim()}`);
				} catch (e) {
					this.show('fail', `Saved, but applying failed:\n${e.message}`);
				}
			}
			await this.refresh();
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
		addTunnel() {
			let i = 0;
			while (this.ifaces.some(r => r.name === `wg${i}`)) i++;
			const name = `wg${i}`;
			this.tunnels.push({ name, port: String(51820 + i), public: '', comment: '', peers: [], export: '' });
			this.ifaces.push({ name, role: 'lan', comment: 'WireGuard', addrMode: 'static', addr: `10.99.${i}.1/24`,
				addr6Mode: 'none', addr6: '', dhcpStart: '', dhcpEnd: '' });
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
				const kp = parseKV(await api('wgkeypair', { body: '' }));
				const addr = this.nextPeerAddr(t);
				const own = this.ifaceOf(t.name).addr;
				const net = network(own);
				// the tunnel subnet and the lans behind this firewall
				const lans = [...new Set(this.ifaces.filter(r => r.role === 'lan' && r.name !== t.name)
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
		saveCtid() { try { localStorage.setItem('pxmxfw.ctid', this.ctidValue); } catch (e) { /* no storage */ } },
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
