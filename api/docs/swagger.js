/**
 * @openapi
 * /api/block-lists:
 *   get:
 *     summary: Check if a domain is blocked by known DNS blocklists
 *     description: |
 *       This endpoint checks whether a given website (by URL) is blocked by various known DNS-based blocklists
 *       such as AdGuard, OpenDNS, Norton Family, Yandex Safe, etc.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: The full URL (e.g. https://example.com) to check
 *     responses:
 *       200:
 *         description: Returns blocklist check results for each DNS server
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 blocklists:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       server:
 *                         type: string
 *                         description: Name of the DNS service
 *                       serverIp:
 *                         type: string
 *                         format: ipv4
 *                         description: IP address of the DNS server
 *                       isBlocked:
 *                         type: boolean
 *                         description: Whether the DNS server blocks the given domain
 *       400:
 *         description: Missing or invalid URL parameter
 *       500:
 *         description: Internal server error
 */

/**
 * @openapi
 * /api/dns-server:
 *   get:
 *     summary: Resolve IPv4 addresses and reverse-hostnames for a domain
 *     description: |
 *       This endpoint resolves the IPv4 addresses for a domain and attempts a reverse DNS lookup.
 *       It also checks whether each address supports DNS-over-HTTPS (DoH) by sending a probe to `/dns-query`.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: The domain or URL to resolve, e.g. https://example.com
 *     responses:
 *       200:
 *         description: Resolved IPv4 addresses with hostname and DoH support info
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 domain:
 *                   type: string
 *                   description: The cleaned domain name
 *                 dns:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       address:
 *                         type: string
 *                         format: ipv4
 *                         description: Resolved IPv4 address
 *                       hostname:
 *                         type: array
 *                         items: { type: string }
 *                         description: Reverse-resolved hostname (if any)
 *                       dohDirectSupports:
 *                         type: boolean
 *                         description: Whether the IP supports DNS-over-HTTPS via `/dns-query`
 *       400:
 *         description: Missing or invalid URL
 *       500:
 *         description: DNS resolution or DoH check failed
 */
/**
 * @openapi
 * /api/dns:
 *   get:
 *     summary: Perform a full DNS lookup for a domain
 *     description: |
 *       This endpoint resolves various DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, PTR)
 *       for a given domain or URL.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: The domain or URL to resolve (e.g. https://example.com)
 *     responses:
 *       200:
 *         description: Resolved DNS records
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 A:
 *                   type: object
 *                   additionalProperties: true
 *                   description: IP address from DNS A record
 *                 AAAA:
 *                   type: array
 *                   items: { type: string }
 *                   description: IPv6 addresses from AAAA records
 *                 MX:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       exchange: { type: string }
 *                       priority: { type: integer }
 *                 TXT:
 *                   type: array
 *                   items:
 *                     type: array
 *                     items: { type: string }
 *                 NS:
 *                   type: array
 *                   items: { type: string }
 *                 CNAME:
 *                   type: array
 *                   items: { type: string }
 *                 SOA:
 *                   type: object
 *                   additionalProperties: true
 *                 SRV:
 *                   type: array
 *                   items: { type: object }
 *                 PTR:
 *                   type: array
 *                   items: { type: string }
 *       400:
 *         description: Missing or invalid URL
 *       500:
 *         description: DNS resolution failed
 */
/**
 * @openapi
 * /api/cookies:
 *   get:
 *     summary: Retrieve HTTP and browser cookies for a URL
 *     description: |
 *       This endpoint fetches cookies in two ways:
 *       - **HTTP-only cookies** via Axios (from `Set-Cookie` headers).
 *       - **Browser-accessible cookies** via Puppeteer (executing JS & DOM access).
 *
 *       This can help analyze how a site sets cookies both on the server and in the client.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: The URL to analyze for cookies (e.g. https://example.com)
 *     responses:
 *       200:
 *         description: Cookie data collected via HTTP headers and browser simulation
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 headerCookies:
 *                   type: array
 *                   items: { type: string }
 *                   description: Cookies from the HTTP response `Set-Cookie` headers
 *                 clientCookies:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       name: { type: string }
 *                       value: { type: string }
 *                       domain: { type: string }
 *                       path: { type: string }
 *                       expires: { type: integer }
 *                       httpOnly: { type: boolean }
 *                       secure: { type: boolean }
 *                       sameSite: { type: string }
 *                 skipped:
 *                   type: string
 *                   description: Message if no cookies were found
 *                 error:
 *                   type: string
 *                   description: Error message, if request failed
 *       400:
 *         description: Missing or invalid `url` query parameter
 *       500:
 *         description: Internal server or Puppeteer error
 */
/**
 * @openapi
 * /api/firewall:
 *   get:
 *     summary: Detect Web Application Firewall (WAF) used by a website
 *     description: |
 *       This endpoint inspects HTTP headers to identify if the site is behind a known WAF,
 *       such as Cloudflare, AWS WAF, Akamai, Sucuri, Imperva, etc.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: The target website URL to check
 *     responses:
 *       200:
 *         description: WAF detection result
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 hasWaf:
 *                   type: boolean
 *                 waf:
 *                   type: string
 *                   nullable: true
 *                   description: The name of the detected WAF (if any)
 *       500:
 *         description: Request or network error
 */
/**
 * @openapi
 * /api/get-ip:
 *   get:
 *     summary: Get IP address and IP family of a domain
 *     description: |
 *       This endpoint performs a DNS lookup to resolve the IP address of a given domain or URL.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: Domain or full URL to resolve (e.g. https://example.com)
 *     responses:
 *       200:
 *         description: IP lookup result
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ip:
 *                   type: string
 *                   format: ipv4
 *                   description: Resolved IP address
 *                 family:
 *                   type: integer
 *                   enum: [4, 6]
 *                   description: IP address family (4 or 6)
 *       500:
 *         description: DNS resolution failed
 */
/**
 * @openapi
 * /api/headers:
 *   get:
 *     summary: Fetch all HTTP response headers from a given URL
 *     description: |
 *       Sends a GET request to the given URL and returns all HTTP response headers, regardless of status code.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: The target URL to fetch headers from
 *     responses:
 *       200:
 *         description: Response headers from the server
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               additionalProperties: true
 *       500:
 *         description: Error while fetching headers
 */
/**
 * @openapi
 * /api/http-security:
 *   get:
 *     summary: Analyze HTTP response for basic security headers
 *     description: |
 *       Checks for presence of key HTTP security headers like Strict-Transport-Security,
 *       X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, and Content-Security-Policy.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: The target website URL to analyze
 *     responses:
 *       200:
 *         description: Security headers analysis
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 strictTransportPolicy: { type: boolean }
 *                 xFrameOptions: { type: boolean }
 *                 xContentTypeOptions: { type: boolean }
 *                 xXSSProtection: { type: boolean }
 *                 contentSecurityPolicy: { type: boolean }
 *       500:
 *         description: Network or request error
 */
/**
 * @openapi
 * /api/linked-pages:
 *   get:
 *     summary: Extract internal and external links from a webpage
 *     description: |
 *       Parses the given URL's HTML and extracts internal and external anchor links, sorted by frequency of appearance.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: URL to analyze for links
 *     responses:
 *       200:
 *         description: Lists of internal and external links found on the page
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 internal:
 *                   type: array
 *                   items: { type: string }
 *                 external:
 *                   type: array
 *                   items: { type: string }
 *       400:
 *         description: No links found or page uses client-side rendering only
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 skipped: { type: string }
 *       500:
 *         description: Failed to fetch or parse the target page
 */
/**
 * @openapi
 * /api/mail-config:
 *   get:
 *     summary: Inspect domain email configuration
 *     description: |
 *       This endpoint resolves MX and TXT DNS records to detect mail services (e.g., Google Workspace, Zoho, ProtonMail),
 *       and extracts SPF, DKIM, and DMARC TXT records.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: The domain or URL to inspect for email configuration
 *     responses:
 *       200:
 *         description: Email DNS records and provider identification
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 mxRecords:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       priority: { type: integer }
 *                       exchange: { type: string }
 *                 txtRecords:
 *                   type: array
 *                   items: { type: array, items: { type: string } }
 *                 mailServices:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       provider: { type: string }
 *                       value: { type: string }
 *                 skipped:
 *                   type: string
 *       500:
 *         description: DNS error or unknown error
 */
/**
 * @openapi
 * /api/ports:
 *   get:
 *     summary: Scan common open ports on a domain
 *     description: |
 *       Checks whether commonly used ports (e.g., 80, 443, 22, 3306, 8080) are open or closed on the target domain.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: The domain to scan (e.g. https://example.com)
 *     responses:
 *       200:
 *         description: Lists of open and closed (failed) ports
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 openPorts:
 *                   type: array
 *                   items: { type: integer }
 *                 failedPorts:
 *                   type: array
 *                   items: { type: integer }
 *       444:
 *         description: Timeout before completion
 *       500:
 *         description: Internal error
 */
/**
 * @openapi
 * /api/quality:
 *   get:
 *     summary: Get Google Lighthouse site quality report
 *     description: |
 *       Uses the PageSpeed Insights API to fetch Lighthouse metrics including Performance, Accessibility,
 *       SEO, PWA readiness, and Best Practices.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: Full URL of the site to evaluate
 *     responses:
 *       200:
 *         description: PageSpeed Insights full JSON report
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       500:
 *         description: Missing API key or fetch failure
 */
/**
 * @openapi
 * /api/robots-txt:
 *   get:
 *     summary: Fetch and parse the robots.txt file from a domain
 *     description: |
 *       Retrieves the robots.txt file and parses its user-agent, allow, and disallow directives.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: The website URL to check (e.g. https://example.com)
 *     responses:
 *       200:
 *         description: Parsed robots.txt rules
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 robots:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       lbl: { type: string }
 *                       val: { type: string }
 *                 skipped:
 *                   type: string
 *       400:
 *         description: Invalid URL
 *       500:
 *         description: Network or fetch error
 */
/**
 * @openapi
 * /api/security-txt:
 *   get:
 *     summary: Check for and parse the security.txt file
 *     description: |
 *       Searches for a security.txt file in common locations and returns parsed fields and PGP signature presence.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: The domain to check (e.g. https://example.com)
 *     responses:
 *       200:
 *         description: Parsed security.txt content or not present
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 isPresent: { type: boolean }
 *                 foundIn: { type: string, nullable: true }
 *                 isPgpSigned: { type: boolean, nullable: true }
 *                 content: { type: string, nullable: true }
 *                 fields:
 *                   type: object
 *                   additionalProperties: { type: string }
 *       500:
 *         description: Failed to fetch or parse security.txt
 */
/**
 * @openapi
 * /api/sitemap:
 *   get:
 *     summary: Fetch and parse sitemap from a domain
 *     description: |
 *       Attempts to retrieve sitemap.xml or find a sitemap via robots.txt, and returns parsed XML as JSON.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: Base URL to retrieve sitemap from (e.g. https://example.com)
 *     responses:
 *       200:
 *         description: Parsed sitemap XML as JSON
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       400:
 *         description: Sitemap not found
 *       500:
 *         description: Request or parse failure
 */
/**
 * @openapi
 * /api/social-tags:
 *   get:
 *     summary: Extract social and metadata tags from a page
 *     description: |
 *       Retrieves HTML and extracts meta tags for SEO, OpenGraph, Twitter, and other embedded metadata.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: URL to extract social tags from
 *     responses:
 *       200:
 *         description: Metadata tags parsed from the HTML head
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               additionalProperties: true
 *       500:
 *         description: Fetching or parsing error
 */
/**
 * @openapi
 * /api/tech-stack:
 *   get:
 *     summary: Detect tech stack for a given URL
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *         description: The full URL to analyze, e.g. https://example.com
 *     responses:
 *       '200':
 *         description: Analysis result
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 technologies:
 *                   type: array
 *                   items:
 *                     type: object
 *       '400':
 *         description: Missing or invalid `url` parameter
 *       '500':
 *         description: Internal error
 */
/**
 * @openapi
 * /api/ssl:
 *   get:
 *     summary: Retrieve SSL certificate details
 *     description: |
 *       Connects to a domain over TLS and returns certificate metadata like issuer, validity, subject, and SANs.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: The URL or domain to check (e.g. https://example.com)
 *     responses:
 *       200:
 *         description: SSL certificate metadata
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               additionalProperties: true
 *       500:
 *         description: Connection or certificate fetch error
 */
/**
 * @openapi
 * /api/tls:
 *   get:
 *     summary: Analyze TLS configuration using Mozilla TLS Observatory
 *     description: |
 *       Triggers a scan using Mozilla TLS Observatory API and returns the full analysis report.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: The domain to scan (e.g. https://example.com)
 *     responses:
 *       200:
 *         description: TLS Observatory report
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               additionalProperties: true
 *       500:
 *         description: Failed to scan domain
 */
/**
 * @openapi
 * /api/threats:
 *   get:
 *     summary: Check URL against threat intelligence services
 *     description: |
 *       Aggregates results from Google Safe Browsing, URLHaus, PhishTank, and Cloudmersive to determine if a URL is malicious.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: The full URL to check
 *     responses:
 *       200:
 *         description: Threat intelligence results
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 urlHaus: { type: object, additionalProperties: true }
 *                 phishTank: { type: object, additionalProperties: true }
 *                 cloudmersive: { type: object, additionalProperties: true }
 *                 safeBrowsing: { type: object, additionalProperties: true }
 *       500:
 *         description: All services failed or network error
 */
/**
 * @openapi
 * /api/txt-records:
 *   get:
 *     summary: Retrieve and parse DNS TXT records for a domain
 *     description: |
 *       Resolves TXT records (like SPF, DKIM, DMARC, verifications) and parses them into key-value pairs.
 *     parameters:
 *       - in: query
 *         name: url
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *         description: URL or domain to resolve (e.g. https://example.com)
 *     responses:
 *       200:
 *         description: Parsed TXT records as key-value object
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               additionalProperties: { type: string }
 *       500:
 *         description: DNS resolution failed or invalid URL
 */
