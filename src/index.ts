#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { google } from 'googleapis';
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { OAuth2Client } from 'google-auth-library';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import open from 'open';
import os from 'os';
import {createEmailMessage} from "./utl.js";
import emailAddresses from 'email-addresses';
const { parseAddressList } = emailAddresses;
type ParsedMailbox = emailAddresses.ParsedMailbox;
type ParsedGroup = emailAddresses.ParsedGroup;

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration paths
const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp');
const OAUTH_PATH = process.env.GMAIL_OAUTH_PATH || path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
const CREDENTIALS_PATH = process.env.GMAIL_CREDENTIALS_PATH || path.join(CONFIG_DIR, 'credentials.json');

// Type definitions for Gmail API responses
interface GmailMessagePart {
    partId?: string;
    mimeType?: string;
    filename?: string;
    headers?: Array<{
        name: string;
        value: string;
    }>;
    body?: {
        attachmentId?: string;
        size?: number;
        data?: string;
    };
    parts?: GmailMessagePart[];
}

interface EmailAttachment {
    id: string;
    filename: string;
    mimeType: string;
    size: number;
}

interface EmailContent {
    text: string;
    html: string;
}

interface EmailAddress {
    address: string;
    name?: string;
}

// OAuth2 configuration
let oauth2Client: OAuth2Client;

/**
 * Recursively extract email body content from MIME message parts
 * Handles complex email structures with nested parts
 */
function extractEmailContent(messagePart: GmailMessagePart): EmailContent {
    // Initialize containers for different content types
    let textContent = '';
    let htmlContent = '';

    // If the part has a body with data, process it based on MIME type
    if (messagePart.body && messagePart.body.data) {
        const content = Buffer.from(messagePart.body.data, 'base64').toString('utf8');

        // Store content based on its MIME type
        if (messagePart.mimeType === 'text/plain') {
            textContent = content;
        } else if (messagePart.mimeType === 'text/html') {
            htmlContent = content;
        }
    }

    // If the part has nested parts, recursively process them
    if (messagePart.parts && messagePart.parts.length > 0) {
        for (const part of messagePart.parts) {
            const { text, html } = extractEmailContent(part);
            if (text) textContent += text;
            if (html) htmlContent += html;
        }
    }

    // Return both plain text and HTML content
    return { text: textContent, html: htmlContent };
}

async function loadCredentials() {
    try {
        // Create config directory if it doesn't exist
        if (!fs.existsSync(CONFIG_DIR)) {
            fs.mkdirSync(CONFIG_DIR, { recursive: true });
        }

        // Check for OAuth keys in current directory first, then in config directory
        const localOAuthPath = path.join(process.cwd(), 'gcp-oauth.keys.json');
        let oauthPath = OAUTH_PATH;

        if (fs.existsSync(localOAuthPath)) {
            fs.copyFileSync(localOAuthPath, OAUTH_PATH);
            console.log('OAuth keys found in current directory, copied to global config.');
        }

        if (!fs.existsSync(OAUTH_PATH)) {
            console.error('Error: OAuth keys file not found. Please place gcp-oauth.keys.json in current directory or', CONFIG_DIR);
            process.exit(1);
        }

        const keysContent = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
        const keys = keysContent.installed || keysContent.web;

        if (!keys) {
            console.error('Error: Invalid OAuth keys file format. File should contain either "installed" or "web" credentials.');
            process.exit(1);
        }

        oauth2Client = new OAuth2Client(
            keys.client_id,
            keys.client_secret,
            'http://localhost:3000/oauth2callback'
        );

        if (fs.existsSync(CREDENTIALS_PATH)) {
            const credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));
            oauth2Client.setCredentials(credentials);
        }
    } catch (error) {
        console.error('Error loading credentials:', error);
        process.exit(1);
    }
}

async function refreshCredentials() {
    try {
        const { credentials: refreshedCredentials } = await oauth2Client.refreshAccessToken();
        oauth2Client.setCredentials(refreshedCredentials);
        fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(refreshedCredentials));
        return true;
    } catch (error) {
        console.error('Error refreshing credentials:', error);
        return false;
    }
}

async function authenticate() {
    const server = http.createServer();
    server.listen(3000);

    return new Promise<void>((resolve, reject) => {
        const authUrl = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            prompt: 'consent',
            scope: ['https://www.googleapis.com/auth/gmail.modify'],
            access_type_extended: true
        });

        console.log('Please visit this URL to authenticate:', authUrl);
        open(authUrl);

        server.on('request', async (req, res) => {
            if (!req.url?.startsWith('/oauth2callback')) return;

            const url = new URL(req.url, 'http://localhost:3000');
            const code = url.searchParams.get('code');

            if (!code) {
                res.writeHead(400);
                res.end('No code provided');
                reject(new Error('No code provided'));
                return;
            }

            try {
                const { tokens } = await oauth2Client.getToken(code);
                oauth2Client.setCredentials(tokens);

                console.log('Refresh token received:', !!tokens.refresh_token);
                console.log('Access token expires in:', tokens.expiry_date ? 
                    new Date(tokens.expiry_date).toLocaleTimeString() : 'N/A');
                
                fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(tokens));

                res.writeHead(200);
                res.end('Authentication successful! You can close this window.');
                server.close();
                resolve();
            } catch (error) {
                res.writeHead(500);
                res.end('Authentication failed');
                reject(error);
            }
        });
    });
}

// Schema definitions
const SendEmailSchema = z.object({
    to: z.array(z.string()).describe("List of recipient email addresses"),
    subject: z.string().describe("Email subject"),
    body: z.string().describe("Email body content"),
    cc: z.array(z.string()).optional().describe("List of CC recipients"),
    bcc: z.array(z.string()).optional().describe("List of BCC recipients"),
    label: z.string().optional().describe("Gmail label to apply to the email thread"),
});

// Add new ReplyEmailSchema
const ReplyEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to reply to"),
    body: z.string().describe("Reply message content"),
    replyAll: z.boolean().optional().describe("Whether to reply to all recipients (default: false)"),
});

const ReadEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to retrieve"),
});

const SearchEmailsSchema = z.object({
    query: z.string().describe("Gmail search query (e.g., 'from:example@gmail.com')"),
    maxResults: z.number().optional().describe("Maximum number of results to return"),
});

// Updated schema to include removeLabelIds
const ModifyEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to modify"),
    labelIds: z.array(z.string()).optional().describe("List of label IDs to apply"),
    addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to the message"),
    removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from the message"),
});

const DeleteEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to delete"),
});

// New schema for listing email labels
const ListEmailLabelsSchema = z.object({}).describe("Retrieves all available Gmail labels");

/**
 * Parse email addresses from a string containing email addresses
 * Returns an array of email addresses without names
 */
function parseEmailAddresses(addressString: string): string[] {
    if (!addressString) return [];
    const parsed = parseAddressList(addressString);
    if (!parsed) return [];
    return parsed.map((addr: ParsedMailbox | ParsedGroup) => {
        if ('address' in addr) {
            return addr.address;
        }
        // For groups, recursively get addresses from group members
        if ('addresses' in addr) {
            return addr.addresses.map(a => a.address).join(',');
        }
        return '';
    }).filter(Boolean);
}

// Main function
async function main() {
    await loadCredentials();
    if (process.argv[2] === 'auth') {
        const refreshed = await refreshCredentials();
        if (process.argv.includes('--force') || !refreshed) {
            await authenticate();
            console.log('Authentication completed successfully');
        }
        else if (refreshed) {
            console.log('Successfully refreshed existing credentials');
        }
        process.exit(0);
    }

    // Initialize Gmail API
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    // Server implementation
    const server = new Server({
        name: "gmail",
        version: "1.0.0",
        capabilities: {
            tools: {},
        },
    });

    // Tool handlers
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: [
            {
                name: "send_email",
                description: "Sends a new email",
                inputSchema: zodToJsonSchema(SendEmailSchema),
            },
            {
                name: "reply_to_email",
                description: "Replies to an existing email thread",
                inputSchema: zodToJsonSchema(ReplyEmailSchema),
            },
            {
                name: "draft_email",
                description: "Draft a new email",
                inputSchema: zodToJsonSchema(SendEmailSchema),
            },
            {
                name: "read_email",
                description: "Retrieves the content of a specific email",
                inputSchema: zodToJsonSchema(ReadEmailSchema),
            },
            {
                name: "search_emails",
                description: "Searches for emails using Gmail search syntax",
                inputSchema: zodToJsonSchema(SearchEmailsSchema),
            },
            {
                name: "modify_email",
                description: "Modifies email labels (move to different folders)",
                inputSchema: zodToJsonSchema(ModifyEmailSchema),
            },
            {
                name: "delete_email",
                description: "Permanently deletes an email",
                inputSchema: zodToJsonSchema(DeleteEmailSchema),
            },
            {
                name: "list_email_labels",
                description: "Retrieves all available Gmail labels",
                inputSchema: zodToJsonSchema(ListEmailLabelsSchema),
            },
        ],
    }))

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
        const { name, arguments: args } = request.params;
        if (process.argv.includes('--auto-refresh')) {
            refreshCredentials();
        }

        async function handleEmailAction(action: "send" | "draft", validatedArgs: any) {
            const message = createEmailMessage(validatedArgs);

            const encodedMessage = Buffer.from(message).toString('base64')
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=+$/, '');

            if (action === "send") {
                const response = await gmail.users.messages.send({
                    userId: 'me',
                    requestBody: {
                        raw: encodedMessage,
                    },
                });

                // If label is provided, create or find the label and apply it
                if (validatedArgs.label) {
                    try {
                        // First, try to find if the label already exists
                        const labelsResponse = await gmail.users.labels.list({ userId: 'me' });
                        let label = labelsResponse.data.labels?.find(l => 
                            l.name?.toLowerCase() === validatedArgs.label.toLowerCase()
                        );

                        // If label doesn't exist, create it
                        if (!label) {
                            const createResponse = await gmail.users.labels.create({
                                userId: 'me',
                                requestBody: {
                                    name: validatedArgs.label,
                                    labelListVisibility: 'labelShow',
                                    messageListVisibility: 'show',
                                },
                            });
                            label = createResponse.data;
                        }

                        // Apply the label to the message
                        await gmail.users.messages.modify({
                            userId: 'me',
                            id: response.data.id!,
                            requestBody: {
                                addLabelIds: [label.id!],
                            },
                        });
                    } catch (error) {
                        console.error('Error applying label:', error);
                        // Continue even if labeling fails
                    }
                }

                return {
                    content: [
                        {
                            type: "text",
                            text: `Email sent successfully\nMessage ID: ${response.data.id}\nThread ID: ${response.data.threadId}${
                                validatedArgs.label ? `\nLabeled with: ${validatedArgs.label}` : ''
                            }`,
                        },
                    ],
                };
            } else {
                const response = await gmail.users.drafts.create({
                    userId: 'me',
                    requestBody: {
                        message: {
                            raw: encodedMessage,
                        },
                    },
                });
                return {
                    content: [
                        {
                            type: "text",
                            text: `Email draft created successfully with ID: ${response.data.id}`,
                        },
                    ],
                };
            }
        }

        try {
            switch (name) {
                case "send_email":
                case "draft_email": {
                    const validatedArgs = SendEmailSchema.parse(args);
                    const action = name === "send_email" ? "send" : "draft";
                    return await handleEmailAction(action, validatedArgs);
                }

                case "reply_to_email": {
                    const validatedArgs = ReplyEmailSchema.parse(args);
                    
                    // Get the original message to extract headers and content
                    const originalMessage = await gmail.users.messages.get({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        format: 'full',
                        metadataHeaders: ['Subject', 'From', 'To', 'Cc', 'Message-ID', 'References', 'In-Reply-To', 'Thread-Index', 'Thread-Topic', 'Date'],
                    });

                    const headers = originalMessage.data.payload?.headers || [];
                    const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '';
                    const from = headers.find(h => h.name?.toLowerCase() === 'from')?.value || '';
                    const to = headers.find(h => h.name?.toLowerCase() === 'to')?.value || '';
                    const cc = headers.find(h => h.name?.toLowerCase() === 'cc')?.value || '';
                    const messageId = headers.find(h => h.name?.toLowerCase() === 'message-id')?.value || '';
                    const references = headers.find(h => h.name?.toLowerCase() === 'references')?.value || '';

                    // Parse email addresses using the utility function
                    const fromEmail = parseEmailAddresses(from)[0] || '';
                    const toEmails = parseEmailAddresses(to).filter(email => email !== fromEmail);
                    const ccEmails = parseEmailAddresses(cc).filter(email => email !== fromEmail);

                    const newReferences = references ? `${references} ${messageId}` : messageId;
                    
                    // Prepare recipients
                    const recipients = validatedArgs.replyAll ? 
                        {
                            to: [fromEmail], // Only send to original sender
                            cc: [...ccEmails] // In reply-all, put other recipients in CC
                        } : 
                        {
                            to: [fromEmail], // Only send to original sender
                            cc: [] // No CC for regular reply
                        };

                    // Generate a unique Message-ID for our reply
                    const newMessageId = `<${Date.now()}.${Math.random().toString(36).substr(2)}@gmail.com>`;
                    
                    // Build References header
                    const refHeader = [from, toEmails.join(' ')].filter(Boolean).join(' ');

                    // Extract original message content
                    const { text, html } = extractEmailContent(originalMessage.data.payload as GmailMessagePart || {});
                    const originalContent = text || html || '';

                    // Format the quoted text with > prefix and add original sender info
                    const quotedText = `\n\nOn ${headers.find(h => h.name?.toLowerCase() === 'date')?.value || ''}, ${from} wrote:\n` + 
                        originalContent.split('\n').map(line => `> ${line}`).join('\n');

                    // Create reply message with proper headers and quoted text
                    const message = createEmailMessage({
                        ...recipients,
                        subject: subject,
                        body: validatedArgs.body + quotedText,
                        headers: {
                            'Message-ID': newMessageId,
                            'In-Reply-To': messageId,
                            'References': newReferences
                        }
                    });

                    const encodedMessage = Buffer.from(message).toString('base64')
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=+$/, '');

                    const response = await gmail.users.messages.send({
                        userId: 'me',
                        requestBody: {
                            threadId: originalMessage.data.threadId,
                            raw: encodedMessage
                        },
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Reply sent successfully with ID: ${response.data.id}`,
                            },
                        ],
                    };
                }

                case "read_email": {
                    const validatedArgs = ReadEmailSchema.parse(args);
                    const response = await gmail.users.messages.get({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        format: 'full',
                    });

                    const headers = response.data.payload?.headers || [];
                    const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '';
                    const from = headers.find(h => h.name?.toLowerCase() === 'from')?.value || '';
                    const to = headers.find(h => h.name?.toLowerCase() === 'to')?.value || '';
                    const date = headers.find(h => h.name?.toLowerCase() === 'date')?.value || '';

                    // Get label names for the message
                    const labelIds = response.data.labelIds || [];
                    let labelNames = '';
                    if (labelIds.length > 0) {
                        const labelsResponse = await gmail.users.labels.list({ userId: 'me' });
                        const labels = labelsResponse.data.labels || [];
                        const messageLabels = labelIds
                            .map(id => labels.find(l => l.id === id)?.name)
                            .filter(Boolean);
                        if (messageLabels.length > 0) {
                            labelNames = `\nLabels: ${messageLabels.join(', ')}`;
                        }
                    }

                    // Extract email content using the recursive function
                    const { text, html } = extractEmailContent(response.data.payload as GmailMessagePart || {});

                    // Use plain text content if available, otherwise use HTML content
                    let body = text || html || '';

                    // If we only have HTML content, add a note for the user
                    const contentTypeNote = !text && html ?
                        '[Note: This email is HTML-formatted. Plain text version not available.]\n\n' : '';

                    // Get attachment information
                    const attachments: EmailAttachment[] = [];
                    const processAttachmentParts = (part: GmailMessagePart, path: string = '') => {
                        if (part.body && part.body.attachmentId) {
                            const filename = part.filename || `attachment-${part.body.attachmentId}`;
                            attachments.push({
                                id: part.body.attachmentId,
                                filename: filename,
                                mimeType: part.mimeType || 'application/octet-stream',
                                size: part.body.size || 0
                            });
                        }

                        if (part.parts) {
                            part.parts.forEach((subpart: GmailMessagePart) =>
                                processAttachmentParts(subpart, `${path}/parts`)
                            );
                        }
                    };

                    if (response.data.payload) {
                        processAttachmentParts(response.data.payload as GmailMessagePart);
                    }

                    // Add attachment info to output if any are present
                    const attachmentInfo = attachments.length > 0 ?
                        `\n\nAttachments (${attachments.length}):\n` +
                        attachments.map(a => `- ${a.filename} (${a.mimeType}, ${Math.round(a.size/1024)} KB)`).join('\n') : '';

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Subject: ${subject}\nFrom: ${from}\nTo: ${to}\nDate: ${date}${labelNames}\n\n${contentTypeNote}${body}${attachmentInfo}`,
                            },
                        ],
                    };
                }

                case "search_emails": {
                    const validatedArgs = SearchEmailsSchema.parse(args);
                    const response = await gmail.users.messages.list({
                        userId: 'me',
                        q: validatedArgs.query,
                        maxResults: validatedArgs.maxResults || 10,
                    });

                    // Get all labels once to avoid multiple API calls
                    const labelsResponse = await gmail.users.labels.list({ userId: 'me' });
                    const allLabels = labelsResponse.data.labels || [];

                    const messages = response.data.messages || [];
                    const results = await Promise.all(
                        messages.map(async (msg) => {
                            const detail = await gmail.users.messages.get({
                                userId: 'me',
                                id: msg.id!,
                                format: 'metadata',
                                metadataHeaders: ['Subject', 'From', 'Date'],
                            });
                            const headers = detail.data.payload?.headers || [];
                            
                            // Get label names for this message
                            const labelNames = (detail.data.labelIds || [])
                                .map(id => allLabels.find(l => l.id === id)?.name)
                                .filter(Boolean);

                            return {
                                id: msg.id,
                                subject: headers.find(h => h.name === 'Subject')?.value || '',
                                from: headers.find(h => h.name === 'From')?.value || '',
                                date: headers.find(h => h.name === 'Date')?.value || '',
                                labels: labelNames.join(', ')
                            };
                        })
                    );

                    return {
                        content: [
                            {
                                type: "text",
                                text: results.map(r =>
                                    `ID: ${r.id}\nSubject: ${r.subject}\nFrom: ${r.from}\nDate: ${r.date}${r.labels ? '\nLabels: ' + r.labels : ''}\n`
                                ).join('\n'),
                            },
                        ],
                    };
                }

                // Updated implementation for the modify_email handler
                case "modify_email": {
                    const validatedArgs = ModifyEmailSchema.parse(args);
                    
                    // Prepare request body
                    const requestBody: any = {};
                    
                    if (validatedArgs.labelIds) {
                        requestBody.addLabelIds = validatedArgs.labelIds;
                    }
                    
                    if (validatedArgs.addLabelIds) {
                        requestBody.addLabelIds = validatedArgs.addLabelIds;
                    }
                    
                    if (validatedArgs.removeLabelIds) {
                        requestBody.removeLabelIds = validatedArgs.removeLabelIds;
                    }
                    
                    await gmail.users.messages.modify({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        requestBody: requestBody,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email ${validatedArgs.messageId} labels updated successfully`,
                            },
                        ],
                    };
                }

                case "delete_email": {
                    const validatedArgs = DeleteEmailSchema.parse(args);
                    await gmail.users.messages.delete({
                        userId: 'me',
                        id: validatedArgs.messageId,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email ${validatedArgs.messageId} deleted successfully`,
                            },
                        ],
                    };
                }

                case "list_email_labels": {
                    const response = await gmail.users.labels.list({
                        userId: 'me',
                    });

                    const labels = response.data.labels || [];
                    const formattedLabels = labels.map(label => ({
                        id: label.id,
                        name: label.name,
                        type: label.type,
                        // Include additional useful information about each label
                        messageListVisibility: label.messageListVisibility,
                        labelListVisibility: label.labelListVisibility,
                        // Only include count if it's a system label (as custom labels don't typically have counts)
                        messagesTotal: label.messagesTotal,
                        messagesUnread: label.messagesUnread,
                        color: label.color
                    }));

                    // Group labels by type (system vs user) for better organization
                    const systemLabels = formattedLabels.filter(label => label.type === 'system');
                    const userLabels = formattedLabels.filter(label => label.type === 'user');

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Found ${labels.length} labels (${systemLabels.length} system, ${userLabels.length} user):\n\n` +
                                    "System Labels:\n" +
                                    systemLabels.map(l => `ID: ${l.id}\nName: ${l.name}\n`).join('\n') +
                                    "\nUser Labels:\n" +
                                    userLabels.map(l => `ID: ${l.id}\nName: ${l.name}\n`).join('\n')
                            },
                        ],
                    };
                }

                default:
                    throw new Error(`Unknown tool: ${name}`);
            }
        } catch (error: any) {
            return {
                content: [
                    {
                        type: "text",
                        text: `Error: ${error.message}`,
                    },
                ],
            };
        }
    });

    const transport = new StdioServerTransport();
    server.connect(transport);
}

main().catch((error) => {
    console.error('Server error:', error);
    process.exit(1);
});