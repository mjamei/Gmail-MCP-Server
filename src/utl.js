export function createEmailMessage({ to, subject, body, cc, bcc, headers = {} }) {
    const emailLines = [
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: 7bit',
        'From: me',
        `To: ${to.join(', ')}`,
        cc && cc.length > 0 ? `Cc: ${cc.join(', ')}` : null,
        bcc && bcc.length > 0 ? `Bcc: ${bcc.join(', ')}` : null,
        `Subject: ${subject}`,
        // Add any additional headers
        ...Object.entries(headers).map(([key, value]) => `${key}: ${value}`),
        '',  // Empty line separates headers from body
        body
    ].filter(Boolean);  // Remove null entries

    return emailLines.join('\r\n');
} 