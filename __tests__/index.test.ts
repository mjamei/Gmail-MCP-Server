import { jest } from '@jest/globals';
import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import fs from 'fs';
import path from 'path';
import http from 'http';
import { 
    extractEmailContent, 
    parseEmailAddresses, 
    loadCredentials, 
    authenticate,
    handleEmailAction,
    readEmail,
    searchEmails,
    initializeGmail,
    gmail
} from '../src/index';

// Mock external dependencies
jest.mock('googleapis');
jest.mock('google-auth-library');
jest.mock('fs');
jest.mock('http');
jest.mock('open');

describe('Gmail MCP Server Tests', () => {
    let mockGmail: any;

    // Reset all mocks before each test
    beforeEach(() => {
        jest.clearAllMocks();

        // Initialize mock Gmail client
        mockGmail = {
            users: {
                messages: {
                    send: jest.fn(),
                    get: jest.fn(),
                    list: jest.fn(),
                    modify: jest.fn(),
                    delete: jest.fn()
                },
                labels: {
                    list: jest.fn(),
                    create: jest.fn()
                },
                drafts: {
                    create: jest.fn()
                }
            }
        };

        (google.gmail as jest.Mock).mockReturnValue(mockGmail);
        const mockAuth = new OAuth2Client();
        initializeGmail(mockAuth);
    });

    describe('parseEmailAddresses', () => {
        test('should parse single email address', () => {
            const input = 'test@example.com';
            expect(parseEmailAddresses(input)).toEqual(['test@example.com']);
        });

        test('should parse multiple email addresses', () => {
            const input = 'test1@example.com, test2@example.com';
            expect(parseEmailAddresses(input)).toEqual(['test1@example.com', 'test2@example.com']);
        });

        test('should parse email addresses with names', () => {
            const input = 'Test User <test@example.com>, Another User <another@example.com>';
            expect(parseEmailAddresses(input)).toEqual(['test@example.com', 'another@example.com']);
        });

        test('should handle empty input', () => {
            expect(parseEmailAddresses('')).toEqual([]);
            // @ts-ignore - Testing undefined input even though type is string
            expect(parseEmailAddresses(undefined)).toEqual([]);
        });

        test('should handle group addresses', () => {
            const input = 'Group: test1@example.com, test2@example.com;';
            expect(parseEmailAddresses(input)).toEqual(['test1@example.com,test2@example.com']);
        });
    });

    describe('extractEmailContent', () => {
        test('should extract plain text content', () => {
            const messagePart = {
                mimeType: 'text/plain',
                body: {
                    data: Buffer.from('Test content').toString('base64')
                }
            };
            expect(extractEmailContent(messagePart)).toEqual({
                text: 'Test content',
                html: ''
            });
        });

        test('should extract HTML content', () => {
            const messagePart = {
                mimeType: 'text/html',
                body: {
                    data: Buffer.from('<p>Test content</p>').toString('base64')
                }
            };
            expect(extractEmailContent(messagePart)).toEqual({
                text: '',
                html: '<p>Test content</p>'
            });
        });

        test('should handle nested multipart messages', () => {
            const messagePart = {
                mimeType: 'multipart/alternative',
                parts: [
                    {
                        mimeType: 'text/plain',
                        body: {
                            data: Buffer.from('Plain text').toString('base64')
                        }
                    },
                    {
                        mimeType: 'text/html',
                        body: {
                            data: Buffer.from('<p>HTML content</p>').toString('base64')
                        }
                    }
                ]
            };
            expect(extractEmailContent(messagePart)).toEqual({
                text: 'Plain text',
                html: '<p>HTML content</p>'
            });
        });

        test('should handle empty message parts', () => {
            const messagePart = {
                mimeType: 'text/plain'
            };
            expect(extractEmailContent(messagePart)).toEqual({
                text: '',
                html: ''
            });
        });
    });

    describe('Gmail API Integration Tests', () => {
        test('should send email successfully', async () => {
            const sendEmailArgs = {
                to: ['recipient@example.com'],
                subject: 'Test Subject',
                body: 'Test Body',
                label: 'TestLabel'
            };

            mockGmail.users.messages.send.mockResolvedValue({
                data: { id: 'test-message-id', threadId: 'test-thread-id' }
            });

            mockGmail.users.labels.list.mockResolvedValue({
                data: { labels: [{ id: 'label-id', name: 'TestLabel' }] }
            });

            const response = await handleEmailAction('send', sendEmailArgs);

            expect(mockGmail.users.messages.send).toHaveBeenCalled();
            expect(response.content[0].text).toContain('Email sent successfully');
            expect(response.content[0].text).toContain('test-message-id');
        });

        test('should create draft successfully', async () => {
            const draftEmailArgs = {
                to: ['recipient@example.com'],
                subject: 'Test Draft',
                body: 'Draft Body'
            };

            mockGmail.users.drafts.create.mockResolvedValue({
                data: { id: 'test-draft-id' }
            });

            const response = await handleEmailAction('draft', draftEmailArgs);

            expect(mockGmail.users.drafts.create).toHaveBeenCalled();
            expect(response.content[0].text).toContain('Email draft created successfully');
            expect(response.content[0].text).toContain('test-draft-id');
        });

        test('should read email successfully', async () => {
            const messageId = 'test-message-id';

            mockGmail.users.messages.get.mockResolvedValue({
                data: {
                    payload: {
                        headers: [
                            { name: 'Subject', value: 'Test Subject' },
                            { name: 'From', value: 'sender@example.com' },
                            { name: 'To', value: 'recipient@example.com' },
                            { name: 'Date', value: '2024-02-24T12:00:00Z' }
                        ],
                        body: {
                            data: Buffer.from('Test content').toString('base64')
                        }
                    },
                    labelIds: ['INBOX']
                }
            });

            mockGmail.users.labels.list.mockResolvedValue({
                data: { labels: [{ id: 'INBOX', name: 'INBOX' }] }
            });

            const response = await readEmail({ messageId });

            expect(mockGmail.users.messages.get).toHaveBeenCalledWith({
                userId: 'me',
                id: messageId,
                format: 'full'
            });
            expect(response.content[0].text).toContain('Test Subject');
            expect(response.content[0].text).toContain('sender@example.com');
            expect(response.content[0].text).toContain('Test content');
        });

        test('should search emails successfully', async () => {
            const searchArgs = {
                query: 'test',
                maxResults: 5
            };

            mockGmail.users.messages.list.mockResolvedValue({
                data: {
                    messages: [
                        { id: 'msg1' },
                        { id: 'msg2' }
                    ]
                }
            });

            mockGmail.users.messages.get.mockImplementation((params: { id: string }) => ({
                data: {
                    id: params.id,
                    payload: {
                        headers: [
                            { name: 'Subject', value: 'Test Subject' },
                            { name: 'From', value: 'sender@example.com' },
                            { name: 'Date', value: '2024-02-24T12:00:00Z' }
                        ]
                    }
                }
            }));

            const response = await searchEmails(searchArgs);

            expect(mockGmail.users.messages.list).toHaveBeenCalledWith({
                userId: 'me',
                q: searchArgs.query,
                maxResults: searchArgs.maxResults
            });
            expect(response.content[0].text).toContain('Test Subject');
            expect(response.content[0].text).toContain('msg1');
            expect(response.content[0].text).toContain('msg2');
        });
    });
}); 