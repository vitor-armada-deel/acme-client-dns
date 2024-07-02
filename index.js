const acme = require('acme-client');
const readline = require('readline');
const dns = require('dns').promises;
const { exec } = require('child_process');
require('dotenv').config();

const directoryUrl = acme.directory.letsencrypt.staging;
const domain = process.env.DOMAIN;

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function checkDNSRecord(domain) {
    return new Promise((resolve, reject) => {
        exec(`dig ${domain} TXT +short @8.8.8.8`, (error, stdout, stderr) => {
            if (error) {
                console.error(`exec error: ${error}`);
                return reject(error);
            }
            if (stderr) {
                console.error(`stderr: ${stderr}`);
                return reject(stderr);
            }
            console.log(`DNS records for ${domain}: ${stdout}`);
            resolve(stdout);
        });
    });
}

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
    const dnsValue = `${keyAuthorization}`;

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

    while (retries < maxRetries && !verified) {
      console.log(`Checking DNS record attempt ${retries + 1}...`);
      try {
        const dnsResult = await checkDNSRecord(dnsRecord);
        if (dnsResult.includes(dnsValue)) {
          console.log('DNS record found, proceeding with verification...');
          verified = true;
        } else {
          console.log('DNS record not yet propagated, retrying...');
        }
      } catch (error) {
        console.error('Failed to retrieve DNS record:', error);
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
