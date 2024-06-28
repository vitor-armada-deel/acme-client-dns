const acme = require('acme-client');
const readline = require('readline');
const dns = require('dns').promises;

require('dotenv').config();

const directoryUrl = acme.directory.letsencrypt.staging;
const domain = process.env.DOMAIN;

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

(async () => {
  try {
    const client = new acme.Client({
      directoryUrl,
      accountKey: await acme.forge.createPrivateKey()
    });

    const email = process.env.EMAIL;
    if (!email) {
      throw new Error('No email provided in .env file');
    }

    await client.createAccount({
      termsOfServiceAgreed: true,
      contact: [`mailto:${email}`]
    });

    const order = await client.createOrder({
      identifiers: [{ type: 'dns', value: domain }]
    });

    const [authorization] = await client.getAuthorizations(order);
    const challenge = authorization.challenges.find(chal => chal.type === 'dns-01');

    const keyAuthorization = await client.getChallengeKeyAuthorization(challenge);

    const dnsRecord = `_acme-challenge.${domain}`;
    const dnsValue = keyAuthorization;

    console.log(`Add the following DNS record to your DNS provider:`);
    console.log(`Host: ${dnsRecord}`);
    console.log(`Type: TXT`);
    console.log(`Value: ${dnsValue}`);

    await new Promise(resolve => {
      rl.question('Press Enter to continue after updating the DNS record...', resolve);
    });

    console.log('Verifying DNS propagation...');

    const maxRetries = 30;
    let retries = 0;
    let verified = false;

    while (retries < maxRetries) {
      try {
        const records = await dns.resolveTxt(dnsRecord);
        if (records.some(record => record.includes(dnsValue))) {
          verified = true;
          break;
        }
      } catch (e) {
        console.log('DNS propagation not yet complete, retrying...');
      }
      await new Promise(resolve => setTimeout(resolve, 30000));
      retries++;
    }

    if (!verified) {
      throw new Error('DNS propagation failed, TXT record not found.');
    }

    console.log('DNS propagation verified, completing challenge...');

    await client.verifyChallenge(authorization, challenge);
    await client.completeChallenge(challenge);
    await client.waitForValidStatus(challenge);

    const [key, csr] = await acme.forge.createCsr({
      commonName: domain
    });
    await client.finalizeOrder(order, csr);

    const certificate = await client.getCertificate(order);
    console.log('Certificate:', certificate);

    const fs = require('fs');
    fs.writeFileSync('certificate.pem', certificate);
    fs.writeFileSync('private-key.pem', key);

    console.log('Certificate and private key have been saved to files.');

    rl.close();
  } catch (e) {
    console.error(e);
    rl.close();
  }
})();
