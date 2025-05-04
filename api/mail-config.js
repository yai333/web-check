import { promises as dns } from 'dns'; // Promise‐based DNS API
import URL from 'url-parse'; // For parsing the incoming URL
import middleware from './_common/middleware.js'; // Your existing middleware wrapper

const mailConfigHandler = async (url, event, context) => {
  // Parse out the hostname (or fallback to pathname)
  const parsed = new URL(url);
  const domain = parsed.hostname || parsed.pathname;

  try {
    // 1. Look up MX records for the domain
    const mxRecords = await dns.resolveMx(domain);

    // 2. Look up all TXT records
    const txtRecordsRaw = await dns.resolveTxt(domain);

    // 3. Filter TXT for email-related entries
    const emailTxtRecords = txtRecordsRaw.filter((record) => {
      const str = record.join('');
      return (
        str.startsWith('v=spf1') ||
        str.startsWith('v=DKIM1') ||
        str.startsWith('v=DMARC1') ||
        str.startsWith('protonmail-verification=') ||
        str.startsWith('google-site-verification=') || // Google Workspace
        str.startsWith('MS=') || // Microsoft 365
        str.startsWith('zoho-verification=') ||
        str.startsWith('titan-verification=') ||
        str.includes('bluehost.com')
      );
    });

    // 4. Map specific providers from TXT records
    const mailServices = emailTxtRecords
      .map((rec) => {
        const s = rec.join('');
        if (s.startsWith('protonmail-verification=')) {
          return { provider: 'ProtonMail', value: s.split('=')[1] };
        }
        if (s.startsWith('google-site-verification=')) {
          return { provider: 'Google Workspace', value: s.split('=')[1] };
        }
        if (s.startsWith('MS=')) {
          return { provider: 'Microsoft 365', value: s.split('=')[1] };
        }
        if (s.startsWith('zoho-verification=')) {
          return { provider: 'Zoho', value: s.split('=')[1] };
        }
        if (s.startsWith('titan-verification=')) {
          return { provider: 'Titan', value: s.split('=')[1] };
        }
        if (s.includes('bluehost.com')) {
          return { provider: 'BlueHost', value: s };
        }
        return null;
      })
      .filter((x) => x !== null);

    // 5. Detect Yahoo via MX
    const yahooMx = mxRecords.find((r) => r.exchange.includes('yahoodns.net'));
    if (yahooMx)
      mailServices.push({ provider: 'Yahoo', value: yahooMx.exchange });

    // 6. Detect Mimecast via MX
    const mimecastMx = mxRecords.find((r) =>
      r.exchange.includes('mimecast.com')
    );
    if (mimecastMx)
      mailServices.push({ provider: 'Mimecast', value: mimecastMx.exchange });

    // 7. Return the combined result
    return {
      mxRecords,
      txtRecords: emailTxtRecords,
      mailServices,
    };
  } catch (error) {
    // Handle domains without mail servers
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return { skipped: 'No mail server in use on this domain' };
    }
    // Other errors
    return {
      statusCode: 500,
      body: { error: error.message },
    };
  }
};

// Wrap and export with your middleware
export const handler = middleware(mailConfigHandler);
export default handler;
