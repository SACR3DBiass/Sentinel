/**
 * ============================================================================
 * CLOUDFLARE EMAIL WORKER
 * ============================================================================
 * Receives incoming emails via Cloudflare Email Routing and forwards
 * parsed data to the FastAPI webhook endpoint for AI analysis.
 *
 * This worker runs on Cloudflare's free tier (100K requests/day).
 *
 * Deployment:
 *   npm install -g wrangler
 *   wrangler login
 *   wrangler deploy
 *
 * ============================================================================
 */

export default {
  /**
   * Main email handler - triggered when an email is received.
   *
   * @param {EmailMessage} message - The incoming email message
   * @param {Env} env - Environment variables (WEBHOOK_URL, WEBHOOK_SECRET)
   * @param {ExecutionContext} ctx - Execution context for async operations
   */
  async email(message, env, ctx) {
    try {
      console.log(`Processing email from ${message.from} to ${message.to}`);

      // Parse the email into structured data
      const emailData = await parseEmail(message);

      // Generate HMAC signature for webhook authentication
      const signature = await generateSignature(
        JSON.stringify(emailData),
        env.WEBHOOK_SECRET
      );

      // Forward to FastAPI backend
      const webhookUrl = `${env.WEBHOOK_URL}/api/v1/webhook/cloudflare`;

      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Webhook-Signature': signature,
          'User-Agent': 'CloudflareEmailWorker/1.0'
        },
        body: JSON.stringify(emailData)
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Webhook failed with status ${response.status}: ${errorText}`);
        // Don't throw - we don't want to bounce the email
      } else {
        const result = await response.json();
        console.log(`Email processed successfully. Threat level: ${result.threat_level}`);
      }

    } catch (error) {
      console.error('Email processing error:', error.message);
      // Log error but don't throw - prevents email bouncing
    }
  }
};

/**
 * Parse email message into structured data format.
 *
 * @param {EmailMessage} message - The incoming email
 * @returns {Object} Parsed email data
 */
async function parseEmail(message) {
  // Extract headers into a plain object
  const headers = {};
  for (const [key, value] of message.headers.entries()) {
    headers[key.toLowerCase()] = value;
  }

  // Get email body content
  let textBody = '';
  let htmlBody = '';

  try {
    textBody = await message.text();
  } catch (e) {
    console.warn('Failed to extract text body:', e.message);
  }

  try {
    htmlBody = await message.html();
  } catch (e) {
    console.warn('Failed to extract HTML body:', e.message);
  }

  // Extract attachment metadata
  const attachments = [];
  if (message.attachments) {
    for (const attachment of message.attachments) {
      attachments.push({
        filename: attachment.filename || 'unknown',
        type: attachment.type || 'application/octet-stream',
        size: attachment.size || 0
      });
    }
  }

  // Generate unique message ID if not present
  const messageId = headers['message-id'] || generateMessageId();

  return {
    message_id: messageId,
    from: message.from,
    to: message.to,
    subject: headers['subject'] || '(No Subject)',
    headers: headers,
    text_body: textBody,
    html_body: htmlBody,
    attachments: attachments,
    timestamp: new Date().toISOString()
  };
}

/**
 * Generate a unique message ID when one isn't provided.
 *
 * @returns {string} Unique message ID
 */
function generateMessageId() {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 11);
  return `<worker-${timestamp}-${random}@phishing-triage>`;
}

/**
 * Generate HMAC-SHA256 signature for webhook authentication.
 *
 * @param {string} data - Data to sign
 * @param {string} secret - Secret key for signing
 * @returns {Promise<string>} Hex-encoded signature
 */
async function generateSignature(data, secret) {
  const encoder = new TextEncoder();

  // Import secret as CryptoKey
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // Generate signature
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(data)
  );

  // Convert to hex string
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Verify HMAC-SHA256 signature.
 *
 * @param {string} data - Original data
 * @param {string} secret - Secret key
 * @param {string} expectedSignature - Signature to verify
 * @returns {Promise<boolean>} True if signature is valid
 */
async function verifySignature(data, secret, expectedSignature) {
  const actualSignature = await generateSignature(data, secret);

  // Use constant-time comparison to prevent timing attacks
  if (actualSignature.length !== expectedSignature.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < actualSignature.length; i++) {
    result |= actualSignature.charCodeAt(i) ^ expectedSignature.charCodeAt(i);
  }

  return result === 0;
}
