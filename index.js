import app from './server.js';

// Log startup for debugging
console.log('Starting webCheckAPI function');

// Export the function that Cloud Functions will invoke
export const webCheckAPI = (req, res) => {
  // Log each request for debugging
  console.log(`Processing request: ${req.method} ${req.url}`);

  // Pass the request to your Express app
  return app(req, res);
};
