// ================================================================
// BACKEND/SERVICES/EMAILSERVICE.JS - EMAIL HANDLING MODULE
// Dedicated email service with templates and SMTP configuration
// ================================================================

const nodemailer = require('nodemailer');
const { logDatabaseOperation } = require('../database/connection');
const { ExternalServiceError, ValidationError } = require('../middleware/errorHandler');

// ================================================================
// EMAIL CONFIGURATION
// ================================================================

const emailConfig = {
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: process.env.SMTP_PORT || 587,
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  },
  tls: {
    rejectUnauthorized: process.env.SMTP_TLS_REJECT_UNAUTHORIZED !== 'false'
  }
};

// Create email transporter
let emailTransporter = null;
if (process.env.SMTP_USER && process.env.SMTP_PASS) {
  emailTransporter = nodemailer.createTransporter(emailConfig);
  
  emailTransporter.verify()
    .then(() => {
      console.log('✅ Email service ready');
    })
    .catch((error) => {
      console.error('❌ Email service configuration error:', error);
    });
} else {
  console.warn('⚠️ Email service not configured - SMTP credentials missing');
}

// ================================================================
// EMAIL TEMPLATES
// ================================================================

const emailTemplates = {
  agentAccountCreated: (data) => ({
    subject: `Welcome to ${process.env.COMPANY_NAME || 'Ideal Plots'} - Agent Account Created`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2c3e50; margin: 0;">${process.env.COMPANY_NAME || 'Ideal Plots'}</h1>
          <p style="color: #7f8c8d; margin: 5px 0;">Professional Real Estate Services</p>
        </div>
        
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px;">
          <h2 style="margin: 0 0 10px 0;">Welcome ${data.name}!</h2>
          <p style="margin: 0; opacity: 0.9;">Your agent account has been created successfully</p>
        </div>
        
        <div style="background: #f8f9fa; padding: 25px; border-radius: 8px; margin: 20px 0;">
          <h3 style="color: #495057; margin-top: 0; border-bottom: 2px solid #dee2e6; padding-bottom: 10px;">Login Credentials</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 8px 0; font-weight: bold; color: #495057;">Email:</td>
              <td style="padding: 8px 0; color: #212529;">${data.email}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0; font-weight: bold; color: #495057;">Temporary Password:</td>
              <td style="padding: 8px 0; font-family: monospace; background: #e9ecef; padding: 5px 8px; border-radius: 4px; color: #212529;">${data.tempPassword}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0; font-weight: bold; color: #495057;">Phone Verification Code:</td>
              <td style="padding: 8px 0; font-family: monospace; background: #e9ecef; padding: 5px 8px; border-radius: 4px; color: #212529;">${data.phoneCode}</td>
            </tr>
          </table>
        </div>
        
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <h4 style="color: #856404; margin-top: 0; display: flex; align-items: center;">
            <span style="margin-right: 8px;">⚠️</span>
            Important Security Instructions
          </h4>
          <ul style="color: #856404; margin: 10px 0; padding-left: 20px;">
            <li>You must change your password on first login</li>
            <li>Verify your email address using the button below</li>
            <li>Verify your phone number using the code provided</li>
            <li>Complete your profile to start receiving client leads</li>
            <li>Never share your login credentials with anyone</li>
          </ul>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${process.env.FRONTEND_URL}/agent/login${data.emailToken ? `?token=${data.emailToken}` : ''}" 
             style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 25px; display: inline-block; font-weight: bold; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);">
            🚀 Login & Verify Account
          </a>
        </div>
        
        <hr style="border: none; border-top: 1px solid #dee2e6; margin: 30px 0;">
        
        <div style="text-align: center; color: #6c757d; font-size: 14px;">
          <p>Need help? Contact our support team at ${process.env.SUPPORT_EMAIL || 'support@idealplots.in'}</p>
          <p><strong>${process.env.COMPANY_NAME || 'Ideal Plots'}</strong><br>Professional Real Estate Services</p>
        </div>
      </div>
    `
  }),

  emailVerification: (data) => ({
    subject: `Verify Your Email Address - ${process.env.COMPANY_NAME || 'Ideal Plots'}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2c3e50;">${process.env.COMPANY_NAME || 'Ideal Plots'}</h1>
          <p style="color: #7f8c8d;">Email Verification Required</p>
        </div>
        
        <div style="background: linear-gradient(135deg, #007bff 0%, #0056b3 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px;">
          <h2 style="margin: 0 0 10px 0;">📧 Verify Your Email</h2>
          <p style="margin: 0; opacity: 0.9;">Hello ${data.name}, please verify your email address</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${process.env.FRONTEND_URL}/verify-email?token=${data.token}" 
             style="background: linear-gradient(135deg, #007bff 0%, #0056b3 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 25px; display: inline-block; font-weight: bold; box-shadow: 0 4px 15px rgba(0, 123, 255, 0.3);">
            ✅ Verify Email Address
          </a>
        </div>
        
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <p style="margin: 0; color: #856404;">
            <strong>Alternative:</strong> Copy and paste this link into your browser:
          </p>
          <p style="word-break: break-all; background: #e9ecef; padding: 10px; border-radius: 4px; margin: 10px 0; font-family: monospace; color: #495057;">
            ${process.env.FRONTEND_URL}/verify-email?token=${data.token}
          </p>
        </div>
        
        <div style="text-align: center; color: #6c757d; font-size: 14px;">
          <p>This verification link will expire in 24 hours.</p>
          <p>If you didn't request this verification, please ignore this email.</p>
        </div>
      </div>
    `
  }),

  passwordReset: (data) => ({
    subject: `Password Reset Request - ${process.env.COMPANY_NAME || 'Ideal Plots'}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2c3e50;">${process.env.COMPANY_NAME || 'Ideal Plots'}</h1>
          <p style="color: #7f8c8d;">Password Reset Request</p>
        </div>
        
        <div style="background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px;">
          <h2 style="margin: 0 0 10px 0;">🔐 Reset Your Password</h2>
          <p style="margin: 0; opacity: 0.9;">Hello ${data.name}, you requested a password reset</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${process.env.FRONTEND_URL}/reset-password?token=${data.token}" 
             style="background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 25px; display: inline-block; font-weight: bold; box-shadow: 0 4px 15px rgba(220, 53, 69, 0.3);">
            🔄 Reset Password
          </a>
        </div>
        
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <p style="margin: 0; color: #721c24;">
            <strong>⚠️ Security Notice:</strong> This reset link will expire in 1 hour for your security.
          </p>
        </div>
        
        <div style="text-align: center; color: #6c757d; font-size: 14px;">
          <p>If you didn't request this reset, please ignore this email and your password will remain unchanged.</p>
        </div>
      </div>
    `
  }),

  propertyStatusUpdate: (data) => ({
    subject: `Property ${data.status === 'approved' ? 'Approved' : 'Update'} - ${data.propertyTitle}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2c3e50;">${process.env.COMPANY_NAME || 'Ideal Plots'}</h1>
        </div>
        
        <div style="background: ${data.status === 'approved' ? '#d4edda' : data.status === 'rejected' ? '#f8d7da' : '#fff3cd'}; 
                    border: 1px solid ${data.status === 'approved' ? '#c3e6cb' : data.status === 'rejected' ? '#f5c6cb' : '#ffeaa7'}; 
                    padding: 20px; border-radius: 8px; margin: 20px 0;">
          <h3 style="color: ${data.status === 'approved' ? '#155724' : data.status === 'rejected' ? '#721c24' : '#856404'}; margin-top: 0;">
            Property Status Update
          </h3>
          <p><strong>Property:</strong> ${data.propertyTitle}</p>
          <p><strong>New Status:</strong> ${data.status.toUpperCase()}</p>
          ${data.notes ? `<p><strong>Admin Notes:</strong> ${data.notes}</p>` : ''}
        </div>
        
        ${data.status === 'approved' ? `
          <div style="text-align: center; margin: 30px 0;">
            <a href="${process.env.FRONTEND_URL}/properties/${data.propertySlug || ''}" 
               style="background: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
              View Live Property
            </a>
          </div>
        ` : ''}
      </div>
    `
  }),

  userWelcome: (data) => ({
    subject: `Welcome to ${process.env.COMPANY_NAME || 'Ideal Plots'}!`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2c3e50;">Welcome ${data.name}!</h1>
          <p style="color: #7f8c8d;">Thank you for joining ${process.env.COMPANY_NAME || 'Ideal Plots'}</p>
        </div>
        
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <h3>What's Next?</h3>
          <ul style="line-height: 1.8;">
            <li>Complete your profile to get better property recommendations</li>
            <li>Set your property preferences and budget</li>
            <li>Start browsing properties in your preferred locations</li>
            <li>Save properties to your favorites for easy access</li>
          </ul>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${process.env.FRONTEND_URL}/properties" 
             style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Browse Properties
          </a>
        </div>
      </div>
    `
  }),

  enquiryUpdate: (data) => ({
    subject: `Update on Your Enquiry ${data.ticketNumber} - ${process.env.COMPANY_NAME || 'Ideal Plots'}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2c3e50;">${process.env.COMPANY_NAME || 'Ideal Plots'}</h1>
          <p style="color: #7f8c8d;">Enquiry Status Update</p>
        </div>
        
        <div style="background: #f8f9fa; padding: 25px; border-radius: 8px; margin: 20px 0;">
          <h3 style="color: #495057; margin-top: 0;">Enquiry Details</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 8px 0; font-weight: bold; color: #495057;">Ticket Number:</td>
              <td style="padding: 8px 0; color: #212529; font-family: monospace;">${data.ticketNumber}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0; font-weight: bold; color: #495057;">Status:</td>
              <td style="padding: 8px 0; color: #212529;">${data.status}</td>
            </tr>
            ${data.agentName ? `
            <tr>
              <td style="padding: 8px 0; font-weight: bold; color: #495057;">Assigned Agent:</td>
              <td style="padding: 8px 0; color: #212529;">${data.agentName}</td>
            </tr>
            ` : ''}
            ${data.notes ? `
            <tr>
              <td style="padding: 8px 0; font-weight: bold; color: #495057;">Message:</td>
              <td style="padding: 8px 0; color: #212529; line-height: 1.6;">${data.notes}</td>
            </tr>
            ` : ''}
          </table>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${process.env.FRONTEND_URL}/track/${data.ticketNumber}" 
             style="background: #17a2b8; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
            📊 Track Your Enquiry
          </a>
        </div>
      </div>
    `
  }),

  agentEnquiryAssignment: (data) => ({
    subject: `New Enquiry Assigned - ${data.ticketNumber || 'Ticket'} | ${process.env.COMPANY_NAME || 'Ideal Plots'}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2c3e50;">${process.env.COMPANY_NAME || 'Ideal Plots'}</h1>
          <p style="color: #7f8c8d;">Professional Real Estate Services</p>
        </div>
        
        <div style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px;">
          <h2 style="margin: 0 0 10px 0;">🎯 New Enquiry Assigned</h2>
          <p style="margin: 0; opacity: 0.9; font-size: 18px;">You have a new client enquiry!</p>
        </div>
        
        <div style="background: white; padding: 25px; border-radius: 8px; margin: 20px 0; border: 1px solid #dee2e6;">
          <h3 style="color: #495057; margin-top: 0;">📋 Enquiry Details</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 12px 0; font-weight: bold; color: #495057;">Agent:</td>
              <td style="padding: 12px 0; color: #212529;">${data.agentName}</td>
            </tr>
            <tr>
              <td style="padding: 12px 0; font-weight: bold; color: #495057;">Ticket:</td>
              <td style="padding: 12px 0; color: #212529; font-family: monospace;">${data.ticketNumber || 'N/A'}</td>
            </tr>
            <tr>
              <td style="padding: 12px 0; font-weight: bold; color: #495057;">Requirements:</td>
              <td style="padding: 12px 0; color: #212529; line-height: 1.6;">${data.requirements}</td>
            </tr>
          </table>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${process.env.FRONTEND_URL}/agent/dashboard" 
             style="background: #007bff; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold; margin-right: 10px;">
            📱 View Dashboard
          </a>
          ${data.clientPhone ? `
          <a href="tel:${data.clientPhone}" 
             style="background: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
            📞 Call Client
          </a>
          ` : ''}
        </div>
      </div>
    `
  }),

  propertyAlert: (data) => ({
    subject: `New Property Alert - ${data.propertyTitle}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2c3e50;">${process.env.COMPANY_NAME || 'Ideal Plots'}</h1>
          <p style="color: #7f8c8d;">New Property Alert</p>
        </div>
        
        <div style="background: #f8f9fa; padding: 25px; border-radius: 8px; margin: 20px 0;">
          <h3 style="color: #495057; margin-top: 0;">${data.propertyTitle}</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 8px 0; font-weight: bold; color: #495057;">Price:</td>
              <td style="padding: 8px 0; color: #212529;">₹${data.price ? data.price.toLocaleString('en-IN') : 'Contact for Price'}</td>
            </tr>
            <tr>
              <td style="padding: 8px 0; font-weight: bold; color: #495057;">Location:</td>
              <td style="padding: 8px 0; color: #212529;">${data.location}</td>
            </tr>
            ${data.bedrooms ? `
            <tr>
              <td style="padding: 8px 0; font-weight: bold; color: #495057;">Bedrooms:</td>
              <td style="padding: 8px 0; color: #212529;">${data.bedrooms}</td>
            </tr>
            ` : ''}
            <tr>
              <td style="padding: 8px 0; font-weight: bold; color: #495057;">Area:</td>
              <td style="padding: 8px 0; color: #212529;">${data.area} sq.ft</td>
            </tr>
          </table>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${process.env.FRONTEND_URL}/properties/${data.slug}" 
             style="background: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
            🏠 View Property Details
          </a>
        </div>
      </div>
    `
  })
};

// ================================================================
// EMAIL SENDING FUNCTIONS
// ================================================================

/**
 * Send email notification
 * @param {Object} emailData - Email data
 * @returns {Promise<Object>} Send result
 */
const sendEmail = async (emailData) => {
  try {
    if (!emailTransporter) {
      throw new ExternalServiceError('Email service not configured');
    }

    const { to, subject, html, text } = emailData;

    if (!to || !subject || !html) {
      throw new ValidationError('Missing required email fields: to, subject, html');
    }

    const mailOptions = {
      from: `"${process.env.COMPANY_NAME || 'Ideal Plots'}" <${process.env.SMTP_FROM_EMAIL || process.env.SMTP_USER}>`,
      to,
      subject,
      html,
      text: text || html.replace(/<[^>]*>/g, '') // Strip HTML for text version
    };

    const result = await emailTransporter.sendMail(mailOptions);

    if (logDatabaseOperation) {
      logDatabaseOperation('email_sent', {
        to,
        subject,
        messageId: result.messageId
      });
    }

    return {
      success: true,
      messageId: result.messageId,
      sentAt: new Date().toISOString()
    };

  } catch (error) {
    console.error('Email sending failed:', error);
    throw new ExternalServiceError(`Email sending failed: ${error.message}`);
  }
};
/**
 * Send password reset email
 * @param {string} to - Recipient email
 * @param {string} name - Recipient name
 * @param {string} token - Reset token
 * @returns {Promise<Object>} Send result
 */
const sendPasswordResetEmail = async (to, name, token) => {
  try {
    if (!to || !name || !token) {
      throw new ValidationError('Missing required fields: to, name, token');
    }

    const template = emailTemplates.passwordReset({
      name,
      token
    });

    return await sendEmail({
      to,
      subject: template.subject,
      html: template.html
    });
  } catch (error) {
    console.error('Password reset email failed:', error);
    throw new ExternalServiceError(`Password reset email failed: ${error.message}`);
  }
};

/**
 * Send bulk emails
 * @param {Array} recipients - List of recipients
 * @param {Object} messageData - Message data
 * @returns {Promise<Object>} Bulk send results
 */
const sendBulkEmails = async (recipients, messageData) => {
  const results = {
    total: recipients.length,
    successful: 0,
    failed: 0,
    errors: []
  };

  for (const recipient of recipients) {
    try {
      const emailResult = await sendEmail({
        to: recipient.email,
        subject: messageData.subject,
        html: messageData.html
      });

      if (emailResult.success) {
        results.successful++;
      } else {
        results.failed++;
        results.errors.push({
          recipient: recipient.email,
          error: emailResult.error || 'Unknown error'
        });
      }
    } catch (error) {
      results.failed++;
      results.errors.push({
        recipient: recipient.email,
        error: error.message
      });
    }
  }

  if (logDatabaseOperation) {
    logDatabaseOperation('bulk_emails_sent', {
      total: results.total,
      successful: results.successful,
      failed: results.failed
    });
  }

  return results;
};

// ================================================================
// EXPORTS
// ================================================================

module.exports = {
  sendEmail,
  sendBulkEmails,
  sendPasswordResetEmail,
  emailTemplates,
  emailTransporter
};