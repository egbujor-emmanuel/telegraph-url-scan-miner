// REAL EXTERNAL API CALL — hits the live URLhaus API with the real
// URLHAUS_AUTH_KEY. Not a mock. Run manually (not part of `npm test`).
import 'dotenv/config';
import { checkUrlhaus } from '../src/providers/urlhaus.js';

const cases = [
  { label: 'real, currently-listed active threat (pulled live from URLhaus csv_recent feed today)', url: 'http://115.49.7.198:54475/i' },
  { label: 'known-safe major domain, should be not_listed', url: 'https://www.wikipedia.org/' },
];

for (const c of cases) {
  console.log(`\n=== ${c.label} ===`);
  console.log('url:', c.url);
  const result = await checkUrlhaus(c.url);
  console.log(JSON.stringify(result, null, 2));
}
