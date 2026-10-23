'use strict';

const assert = require('assert');

const debug = false;

const {
  fixture,
  fixtureKey,
  mustCall,
  setup,
} = require('./common.js');
const {
  AgentProtocol,
  BaseAgent,
  utils: { parseKey },
} = require('../lib/index.js');
const {
  attachCertificate,
  getCertBaseType,
  isCertType,
} = require('../lib/protocol/keyParser.js');

const serverCfg = { hostKeys: [ fixtureKey('ssh_host_rsa_key').raw ] };
const username = 'Cert User';

const certFixtures = [
  {
    name: 'id_ed25519',
    certType: 'ssh-ed25519-cert-v01@openssh.com',
    baseType: 'ssh-ed25519',
    wireAlgo: 'ssh-ed25519-cert-v01@openssh.com',
  },
  {
    name: 'id_ecdsa',
    certType: 'ecdsa-sha2-nistp256-cert-v01@openssh.com',
    baseType: 'ecdsa-sha2-nistp256',
    wireAlgo: 'ecdsa-sha2-nistp256-cert-v01@openssh.com',
  },
  {
    name: 'id_rsa',
    certType: 'ssh-rsa-cert-v01@openssh.com',
    baseType: 'ssh-rsa',
    // The server advertises rsa-sha2-* via server-sig-algs, so the client must
    // use the SHA-2 certificate algorithm name
    wireAlgo: 'rsa-sha2-256-cert-v01@openssh.com',
  },
].map((info) => {
  const keyRaw = fixture(`certs/${info.name}`);
  const certRaw = fixture(`certs/${info.name}-cert.pub`);
  return { ...info, keyRaw, certRaw, cert: parseKey(certRaw) };
});

// Key parser checks
{
  assert.strictEqual(isCertType('ssh-ed25519-cert-v01@openssh.com'), true);
  assert.strictEqual(isCertType('ssh-rsa-cert-v00@openssh.com'), true);
  assert.strictEqual(isCertType('ssh-ed25519'), false);
  assert.strictEqual(getCertBaseType('ssh-rsa-cert-v01@openssh.com'),
                     'ssh-rsa');
  assert.strictEqual(getCertBaseType('ssh-ed25519'), 'ssh-ed25519');

  for (const info of certFixtures) {
    const { cert } = info;
    assert(!(cert instanceof Error), `${info.name}: ${cert}`);
    assert.strictEqual(cert.type, info.certType);
    assert.strictEqual(cert.isPrivateKey(), false);

    // The SSH-format public key is the full certificate blob
    const certBlob =
      Buffer.from(info.certRaw.toString().trim().split(' ')[1], 'base64');
    assert.deepStrictEqual(cert.getPublicSSH(), certBlob);

    // Binary certificate blobs (e.g. from an agent) parse the same way
    const binCert = parseKey(certBlob);
    assert(!(binCert instanceof Error), `${info.name}: ${binCert}`);
    assert.strictEqual(binCert.type, info.certType);
    assert.strictEqual(binCert.getPublicPEM(), cert.getPublicPEM());

    const plainKey = parseKey(info.keyRaw);
    assert.strictEqual(plainKey.type, info.baseType);
    assert.strictEqual(cert.getPublicPEM(), plainKey.getPublicPEM());

    const certKey = attachCertificate(info.keyRaw, info.certRaw);
    assert(!(certKey instanceof Error), `${info.name}: ${certKey}`);
    assert.strictEqual(certKey.type, info.certType);
    assert.strictEqual(certKey.isPrivateKey(), true);
    assert.deepStrictEqual(certKey.getPublicSSH(), certBlob);
    // Attaching must not mutate the original key
    assert.strictEqual(plainKey.type, info.baseType);

    const data = Buffer.from('certificate signing test');
    assert.strictEqual(cert.verify(data, certKey.sign(data)), true);
  }

  // Mismatched key/certificate pairs
  const ecdsaCert = certFixtures[1].certRaw;
  assert.throws(() => {
    const ret = attachCertificate(fixture('id_ecdsa'), ecdsaCert);
    if (ret instanceof Error)
      throw ret;
  }, /Certificate does not match private key/);
  assert.throws(() => {
    const ret = attachCertificate(certFixtures[2].keyRaw, ecdsaCert);
    if (ret instanceof Error)
      throw ret;
  }, /Certificate does not match private key/);
  assert.throws(() => {
    const ret = attachCertificate(certFixtures[0].keyRaw,
                                  fixture('certs/id_ed25519'));
    if (ret instanceof Error)
      throw ret;
  }, /Not an OpenSSH certificate/);
}

function checkCertAuth(conn, info, opts = {}) {
  let authAttempt = 0;
  conn.on('authentication', mustCall((ctx) => {
    assert.strictEqual(ctx.username, username);
    switch (++authAttempt) {
      case 1:
        assert.strictEqual(ctx.method, 'none');
        return ctx.reject();
      case 3:
        assert(ctx.signature, 'Missing publickey signature');
      // FALLTHROUGH
      case 2:
        assert.strictEqual(ctx.method, 'publickey');
        assert.strictEqual(ctx.key.algo, info.certType);
        assert.deepStrictEqual(ctx.key.data, info.cert.getPublicSSH());
        break;
    }
    if (ctx.signature) {
      const key = parseKey(ctx.key.data);
      assert.strictEqual(key.type, info.certType);
      assert.strictEqual(key.verify(ctx.blob, ctx.signature, ctx.hashAlgo),
                         true,
                         'Could not verify publickey signature');
      if (info.wireAlgo.startsWith('rsa-sha2-256'))
        assert.strictEqual(ctx.hashAlgo, 'sha256');
    }
    ctx.accept();
  }, 3)).on('ready', mustCall(() => {
    if (opts.onReady)
      opts.onReady();
    conn.end();
  }));
}

// Signed data includes the wire public key algorithm, so a successful
// verification against a blob containing `info.wireAlgo` proves the client
// sent the correct certificate algorithm name
function blobHasAlgo(blob, algo) {
  return blob.includes(Buffer.from(algo));
}

for (const info of certFixtures) {
  // privateKey + certificate connect options
  {
    const { server } = setup(
      `Certificate authentication (${info.certType}, privateKey)`,
      {
        client: {
          username,
          privateKey: info.keyRaw,
          certificate: info.certRaw,
        },
        server: serverCfg,
        debug,
      }
    );
    server.on('connection', mustCall((conn) => {
      conn.on('authentication', (ctx) => {
        if (ctx.signature)
          assert(blobHasAlgo(ctx.blob, info.wireAlgo), 'Wrong wire algo');
      });
      checkCertAuth(conn, info);
    }));
  }

  // authHandler publickey with certificate
  {
    const { server } = setup(
      `Certificate authentication (${info.certType}, authHandler)`,
      {
        client: {
          username,
          authHandler: mustCall((methodsLeft, partial, cb) => {
            if (methodsLeft === null)
              return 'none';
            return {
              type: 'publickey',
              username,
              key: info.keyRaw,
              certificate: info.certRaw,
            };
          }, 2),
        },
        server: serverCfg,
        debug,
      }
    );
    server.on('connection', mustCall((conn) => {
      checkCertAuth(conn, info);
    }));
  }

  // Agent-provided certificate identity
  {
    let signCount = 0;
    const certKey = attachCertificate(info.keyRaw, info.certRaw);
    class CertAgent extends BaseAgent {
      getIdentities(cb) {
        // Agents only expose the public certificate blob
        cb(null, [ parseKey(info.cert.getPublicSSH()) ]);
      }
      sign(pubKey, data, options, cb) {
        ++signCount;
        assert.strictEqual(pubKey.type, info.certType);
        if (info.baseType === 'ssh-rsa')
          assert.strictEqual(options.hash, 'sha256');
        cb(null, certKey.sign(data, options.hash));
      }
    }
    const { server } = setup(
      `Certificate authentication (${info.certType}, agent)`,
      {
        client: { username, agent: new CertAgent() },
        server: serverCfg,
        debug,
      }
    );
    server.on('connection', mustCall((conn) => {
      conn.on('authentication', (ctx) => {
        if (ctx.signature)
          assert(blobHasAlgo(ctx.blob, info.wireAlgo), 'Wrong wire algo');
      });
      checkCertAuth(conn, info, {
        onReady: () => assert.strictEqual(signCount, 1),
      });
    }));
  }
}

// Mismatched certificate passed via connect options
{
  const { Client } = require('../lib/index.js');
  assert.throws(() => {
    new Client().connect({
      username,
      privateKey: fixture('id_ecdsa'),
      certificate: certFixtures[1].certRaw,
    });
  }, /Cannot use certificate: Certificate does not match private key/);
}

// Certificate type label that does not match the embedded certificate type
{
  const ed25519Cert = certFixtures[0].certRaw.toString().trim().split(' ');
  const ecdsaCert = certFixtures[1].certRaw.toString().trim().split(' ');
  const mislabeled = `${ed25519Cert[0]} ${ecdsaCert[1]}`;
  const ret = parseKey(mislabeled);
  assert(ret instanceof Error, 'Expected error for mislabeled certificate');
}

// AgentProtocol round trip with certificate identities
for (const info of certFixtures) {
  const client = new AgentProtocol(true);
  const server = new AgentProtocol(false);
  const certKey = attachCertificate(info.keyRaw, info.certRaw);
  const buf = Buffer.from('data to sign');

  server.on('identities', mustCall((req) => {
    server.getIdentitiesReply(req, [ info.cert ]);
  }));
  server.on('sign', mustCall((req, pubKey, data, options) => {
    assert.strictEqual(pubKey.type, info.certType);
    assert.deepStrictEqual(pubKey.getPublicSSH(), info.cert.getPublicSSH());
    assert.deepStrictEqual(data, buf);
    if (info.baseType === 'ssh-rsa')
      assert.strictEqual(options.hash, 'sha256');
    else
      assert.strictEqual(options.hash, undefined);
    server.signReply(req, certKey.sign(data, options.hash));
  }));

  client.getIdentities(mustCall((err, keys) => {
    assert(!err, `Unexpected error: ${err}`);
    assert.strictEqual(keys.length, 1);
    assert.strictEqual(keys[0].type, info.certType);
    assert.strictEqual(keys[0].isPrivateKey(), false);
    assert.deepStrictEqual(keys[0].getPublicSSH(), info.cert.getPublicSSH());

    const opts = (info.baseType === 'ssh-rsa' ? { hash: 'sha256' } : {});
    client.sign(keys[0], buf, opts, mustCall((err, signature) => {
      assert(!err, `Unexpected error: ${err}`);
      const hash = (info.baseType === 'ssh-rsa' ? 'sha256' : undefined);
      assert.strictEqual(keys[0].verify(buf, signature, hash), true);
    }));
  }));

  client.pipe(server).pipe(client);
}
