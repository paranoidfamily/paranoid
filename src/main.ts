// paranoidd: node src/main.ts
import { ConfigStore } from './config.ts';
import { SecretStore } from './secrets.ts';
import { Runtime } from './runtime.ts';
import { createServer, loadToken } from './server.ts';
import { log } from './log.ts';

const config = new ConfigStore();
const secrets = new SecretStore(config.dir);
const rt = new Runtime(config, secrets);
const token = loadToken(config.dir);
const { server, listen } = createServer(rt, token);

await listen();
const { host, port } = config.value.listen;
log('daemon.listen', { host, port, profile: config.value.profile });
console.error(`\nPARANOID local runtime\n  UI        http://${host}:${port}/\n  OpenAI    http://${host}:${port}/v1  (bearer token in ${config.dir}${process.platform === 'win32' ? '\\' : '/'}local-token)\n  profile   ${config.value.profile}\n`);

if (config.value.tor.manage && rt.tor.exe) {
  rt.tor.start().then(() => rt.tor.verify()).catch(e => log('tor.start_failed', { name: e?.name }));
} else {
  rt.tor.verify().catch(() => {});
}

function shutdown() {
  log('daemon.stop');
  rt.cover.stop('daemon shutdown');
  rt.sessions.endAll();
  rt.tor.stop();
  server.close();
  setTimeout(() => process.exit(0), 500).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
