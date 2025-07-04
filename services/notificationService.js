// ================================================================
// BACKEND/SERVICES/NOTIFICATIONSERVICE.JS - NOTIFICATION SERVICE
// Handles email, SMS, and push notifications for the platform
// ================================================================

const nodemailer = require('nodemailer');
const twilio = require('twilio');
const { 
  executeQuery, 
  executeTransaction,
  handleDatabaseError,
  logDatabaseOperation
} = require('../database/connection');

const { 
  hashPassword,
  generateVerificationToken,
  generateVerificationCode
} = require('../middleware/auth');

const {
  ValidationError,
  NotFoundError,
  ExternalServiceError
} = require('../middleware/errorHandler');

// ================================================================
// EMAIL CONFIGURATION
// ================================================================

const emailConfig = {
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: process.env.SMTP_PORT || 587,
  secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
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
  
  // Verify email configuration
  emailTransporter.verify()
    .then(() => {
      console.log('✅ Email service ready');
    })
    .catch((error) => {
      console.error('❌ Email service configuration error:', error);
    });
}

// ================================================================
// SMS CONFIGURATION
// ================================================================

let smsClient = null;
if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
  smsClient = twilio(
    process.env.TWILIO_ACCOUNT_SID,
    process.env.TWILIO_AUTH_TOKEN
  );
  console.log('✅ SMS service ready');
}

// ================================================================
// EMAIL TEMPLATES
// ================================================================

const emailTemplates = {
  agentAccountCreated: (data) => ({
    subject: `Welcome to ${process.env.COMPANY_NAME || 'Real Estate Platform'} - Agent Account Created`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2c3e50; margin: 0;">${process.env.COMPANY_NAME || 'Real Estate Platform'}</h1>
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
        
        <div style="background: #e8f4fd; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <h4 style="color: #0c5460; margin-top: 0;">Your Professional Details</h4>
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 5px 0; font-weight: bold; color: #0c5460;">License Number:</td>
              <td style="padding: 5px 0; color: #212529;">${data.licenseNumber}</td>
            </tr>
            <tr>
              <td style="padding: 5px 0; font-weight: bold; color: #0c5460;">Agency:</td>
              <td style="padding: 5px 0; color: #212529;">${data.agencyName}</td>
            </tr>
            <tr>
              <td style="padding: 5px 0; font-weight: bold; color: #0c5460;">Commission Rate:</td>
              <td style="padding: 5px 0; color: #212529;">${data.commissionRate}%</td>
            </tr>
            <tr>
              <td style="padding: 5px 0; font-weight: bold; color: #0c5460;">Experience:</td>
              <td style="padding: 5px 0; color: #212529;">${data.experienceYears} years</td>
            </tr>
          </table>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${process.env.FRONTEND_URL}/agent/login?token=${data.emailToken}" 
             style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 25px; display: inline-block; font-weight: bold; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);">
            🚀 Login & Verify Account
          </a>
        </div>
        
        <div style="background: #f1f3f4; padding: 20px; border-radius: 8px; margin: 30px 0;">
          <h4 style="color: #5f6368; margin-top: 0;">Next Steps:</h4>
          <ol style="color: #5f6368; margin: 10px 0; padding-left: 20px;">
            <li>Click the login button above to access your account</li>
            <li>Change your temporary password to something secure</li>
            <li>Complete your profile with additional details</li>
            <li>Upload your professional photo and documents</li>
            <li>Start receiving and managing client enquiries</li>
          </ol>
        </div>
        
        <hr style="border: none; border-top: 1px solid #dee2e6; margin: 30px 0;">
        
        <div style="text-align: center; color: #6c757d; font-size: 14px;">
          <p>Need help? Contact our support team at ${process.env.SUPPORT_EMAIL || 'support@example.com'}</p>
          <p>This is an automated message, please do not reply to this email.</p>
          <p style="margin-top: 20px;">
            <strong>${process.env.COMPANY_NAME || 'Real Estate Platform'}</strong><br>
            Professional Real Estate Services<br>
            ${process.env.COMPANY_ADDRESS || ''}
          </p>
        </div>
      </div>
    `
  }),

  emailVerification: (data) => ({
    subject: 'Verify Your Email Address',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #2c3e50;">Email Verification Required</h2>
        
        <p>Hello ${data.name},</p>
        
        <p>Please verify your email address by clicking the button below:</p>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${process.env.FRONTEND_URL}/verify-email?token=${data.token}" 
             style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Verify Email Address
          </a>
        </div>
        
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 4px;">
          ${process.env.FRONTEND_URL}/verify-email?token=${data.token}
        </p>
        
        <p>This verification link will expire in 24 hours.</p>
        
        <p>If you didn't request this verification, please ignore this email.</p>
      </div>
    `
  }),

  passwordReset: (data) => ({
    subject: 'Password Reset Request',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #2c3e50;">Password Reset Request</h2>
        
        <p>Hello ${data.name},</p>
        
        <p>You requested a password reset. Click the button below to set a new password:</p>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${process.env.FRONTEND_URL}/reset-password?token=${data.token}" 
             style="background: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Reset Password
          </a>
        </div>
        
        <p>This reset link will expire in 1 hour.</p>
        
        <p>If you didn't request this reset, please ignore this email and your password will remain unchanged.</p>
      </div>
    `
  }),
    agentEnquiryAssignment: (data) => ({
    subject: `New Enquiry Assigned - ${data.ticketNumber || 'Ticket'} | ${process.env.COMPANY_NAME || 'Real Estate Platform'}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f8f9fa;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2c3e50; margin: 0;">${process.env.COMPANY_NAME || 'Real Estate Platform'}</h1>
          <p style="color: #7f8c8d; margin: 5px 0;">Professional Real Estate Services</p>
        </div>
        
        <div style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px;">
          <h2 style="margin: 0 0 10px 0;">🎯 New Enquiry Assigned</h2>
          <p style="margin: 0; opacity: 0.9; font-size: 18px;">You have a new client enquiry!</p>
        </div>
        
        <div style="background: white; padding: 25px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
          <h3 style="color: #495057; margin-top: 0; border-bottom: 2px solid #dee2e6; padding-bottom: 10px;">📋 Enquiry Details</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 12px 0; font-weight: bold; color: #495057; width: 35%;">Agent Name:</td>
              <td style="padding: 12px 0; color: #212529;">${data.agentName}</td>
            </tr>
            <tr>
              <td style="padding: 12px 0; font-weight: bold; color: #495057;">Ticket Number:</td>
              <td style="padding: 12px 0; color: #212529; font-family: monospace; background: #e9ecef; padding: 8px; border-radius: 4px;">${data.ticketNumber || 'N/A'}</td>
            </tr>
            <tr>
              <td style="padding: 12px 0; font-weight: bold; color: #495057;">Client Requirements:</td>
              <td style="padding: 12px 0; color: #212529; line-height: 1.6;">${data.requirements}</td>
            </tr>
            <tr>
              <td style="padding: 12px 0; font-weight: bold; color: #495057;">Priority:</td>
              <td style="padding: 12px 0;">
                <span style="background: #ffc107; color: #212529; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold;">
                  HIGH PRIORITY
                </span>
              </td>
            </tr>
          </table>
        </div>
        
        <div style="background: #e8f4fd; border-left: 4px solid #007bff; padding: 20px; margin: 20px 0;">
          <h4 style="color: #0c5460; margin-top: 0; display: flex; align-items: center;">
            <span style="margin-right: 8px;">💡</span>
            Quick Action Required
          </h4>
          <p style="color: #0c5460; margin: 10px 0; line-height: 1.6;">
            This enquiry has been automatically assigned to you based on your expertise and availability. 
            Please respond within 2 hours for the best client experience.
          </p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${data.dashboardUrl || `${process.env.FRONTEND_URL}/agent/dashboard`}" 
             style="background: linear-gradient(135deg, #007bff 0%, #0056b3 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 25px; display: inline-block; font-weight: bold; box-shadow: 0 4px 15px rgba(0, 123, 255, 0.3); margin-right: 10px;">
            📱 View in Dashboard
          </a>
          <a href="tel:${data.clientPhone || ''}" 
             style="background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 25px; display: inline-block; font-weight: bold; box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3);">
            📞 Call Client
          </a>
        </div>
        
        <hr style="border: none; border-top: 1px solid #dee2e6; margin: 30px 0;">
        
        <div style="text-align: center; color: #6c757d; font-size: 14px;">
          <p>🏆 <strong>Pro Tip:</strong> Quick response times lead to higher conversion rates!</p>
          <p>Need help? Contact support at ${process.env.SUPPORT_EMAIL || 'support@example.com'}</p>
          <p style="margin-top: 20px;">
            <strong>${process.env.COMPANY_NAME || 'Real Estate Platform'}</strong><br>
            Your success is our priority
          </p>
        </div>
      </div>
    `
  }),

  // Property status change notification
  propertyStatusUpdate: (data) => ({
    subject: `Property ${data.status === 'approved' ? 'Approved' : 'Update'} - ${data.propertyTitle}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2c3e50;">${process.env.COMPANY_NAME || 'Real Estate Platform'}</h1>
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
            <a href="${process.env.FRONTEND_URL}/properties/${data.propertySlug}" 
               style="background: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
              View Live Property
            </a>
          </div>
        ` : ''}
      </div>
    `
  }),

  // Welcome email for new users
  userWelcome: (data) => ({
    subject: `Welcome to ${process.env.COMPANY_NAME || 'Real Estate Platform'}!`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2c3e50;">Welcome ${data.name}!</h1>
          <p style="color: #7f8c8d;">Thank you for joining ${process.env.COMPANY_NAME || 'our platform'}</p>
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
  })
};

// ================================================================
// SMS TEMPLATES
// ================================================================

const smsTemplates = {
  agentAccountCreated: (data) => `
Welcome ${data.name}! Your agent account is ready.
Login: ${data.email}
Password: ${data.tempPassword}
Verify Code: ${data.phoneCode}
Login at: ${process.env.FRONTEND_URL}/agent/login
IMPORTANT: Change password on first login.
  `.trim(),

  phoneVerification: (data) => `
Your verification code for ${process.env.COMPANY_NAME || 'Real Estate Platform'} is: ${data.code}
This code expires in 10 minutes.
  `.trim(),

  passwordReset: (data) => `
Your password reset code for ${process.env.COMPANY_NAME || 'Real Estate Platform'} is: ${data.code}
This code expires in 1 hour.
  `.trim(),

  enquiryNotification: (data) => `
New enquiry assigned to you!
Client: ${data.clientName}
Property: ${data.propertyTitle}
Contact: ${data.clientPhone}
Login to view details: ${process.env.FRONTEND_URL}/agent/dashboard
  `.trim(),

  propertyStatusUpdate: (data) => `
Property Update: Your property "${data.propertyTitle}" has been ${data.status}.
${data.status === 'approved' ? 'Congratulations! Your property is now live.' : ''}
${data.notes ? `Note: ${data.notes}` : ''}
View details: ${process.env.FRONTEND_URL}/my-properties
  `.trim(),

  enquiryResponse: (data) => `
Update on your enquiry ${data.ticketNumber}:
Status: ${data.status}
${data.agentName ? `Agent: ${data.agentName}` : ''}
${data.notes ? `Message: ${data.notes}` : ''}
Track: ${process.env.FRONTEND_URL}/track/${data.ticketNumber}
  `.trim(),

  propertyAlert: (data) => `
New property alert! 
${data.propertyTitle} - ₹${data.price}
Location: ${data.location}
${data.bedrooms ? `${data.bedrooms}BHK` : ''} ${data.area}sq.ft
View: ${process.env.FRONTEND_URL}/properties/${data.slug}
  `.trim()
};

// ================================================================
// CORE NOTIFICATION FUNCTIONS
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

    const mailOptions = {
      from: `"${process.env.COMPANY_NAME || 'Real Estate Platform'}" <${process.env.SMTP_FROM_EMAIL || process.env.SMTP_USER}>`,
      to,
      subject,
      html,
      text: text || html.replace(/<[^>]*>/g, '') // Strip HTML for text version
    };

    const result = await emailTransporter.sendMail(mailOptions);

    logDatabaseOperation('email_sent', {
      to,
      subject,
      messageId: result.messageId
    });

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
 * Send SMS notification
 * @param {Object} smsData - SMS data
 * @returns {Promise<Object>} Send result
 */
const sendSMS = async (smsData) => {
  try {
    if (!smsClient) {
      throw new ExternalServiceError('SMS service not configured');
    }

    const { to, body } = smsData;

    const result = await smsClient.messages.create({
      body,
      from: process.env.TWILIO_PHONE_NUMBER,
      to
    });

    logDatabaseOperation('sms_sent', {
      to,
      messageId: result.sid,
      status: result.status
    });

    return {
      success: true,
      messageId: result.sid,
      status: result.status,
      sentAt: new Date().toISOString()
    };

  } catch (error) {
    console.error('SMS sending failed:', error);
    throw new ExternalServiceError(`SMS sending failed: ${error.message}`);
  }
};

/**
 * Send property status update notification
 * @param {Object} data - Property and status data
 * @returns {Promise<Object>} Send result
 */
const sendPropertyStatusNotification = async (data) => {
  try {
    const {
      ownerEmail,
      ownerPhone,
      ownerName,
      propertyTitle,
      status,
      notes,
      propertySlug
    } = data;

    const results = {
      email: { sent: false, error: null },
      sms: { sent: false, error: null }
    };

    // Send email notification
    try {
      const emailTemplate = additionalEmailTemplates.propertyStatusUpdate({
        ownerName,
        propertyTitle,
        status,
        notes,
        propertySlug
      });

      await sendEmail({
        to: ownerEmail,
        subject: emailTemplate.subject,
        html: emailTemplate.html
      });
      results.email.sent = true;
    } catch (error) {
      results.email.error = error.message;
    }

    // Send SMS notification
    try {
      const smsBody = additionalSmsTemplates.propertyStatusUpdate({
        propertyTitle,
        status,
        notes
      });

      await sendSMS({
        to: ownerPhone,
        body: smsBody
      });
      results.sms.sent = true;
    } catch (error) {
      results.sms.error = error.message;
    }

    return results;

  } catch (error) {
    console.error('Error sending property status notification:', error);
    throw error;
  }
};

/**
 * Send enquiry response notification to client
 * @param {Object} data - Enquiry response data
 * @returns {Promise<Object>} Send result
 */
const sendEnquiryResponseNotification = async (data) => {
  try {
    const {
      clientEmail,
      clientPhone,
      clientName,
      ticketNumber,
      status,
      agentName,
      notes
    } = data;

    const results = {
      email: { sent: false, error: null },
      sms: { sent: false, error: null }
    };

    // Send email notification
    try {
      await sendEmail({
        to: clientEmail,
        subject: `Update on Your Enquiry ${ticketNumber}`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #2c3e50;">Enquiry Update</h2>
            
            <p>Dear ${clientName},</p>
            
            <p>We have an update on your enquiry <strong>${ticketNumber}</strong>:</p>
            
            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <p><strong>Status:</strong> ${status}</p>
              ${agentName ? `<p><strong>Assigned Agent:</strong> ${agentName}</p>` : ''}
              ${notes ? `<p><strong>Message:</strong> ${notes}</p>` : ''}
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${process.env.FRONTEND_URL}/track/${ticketNumber}" 
                 style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Track Your Enquiry
              </a>
            </div>
          </div>
        `
      });
      results.email.sent = true;
    } catch (error) {
      results.email.error = error.message;
    }

    // Send SMS notification
    try {
      const smsBody = additionalSmsTemplates.enquiryResponse({
        ticketNumber,
        status,
        agentName,
        notes
      });

      await sendSMS({
        to: clientPhone,
        body: smsBody
      });
      results.sms.sent = true;
    } catch (error) {
      results.sms.error = error.message;
    }

    return results;

  } catch (error) {
    console.error('Error sending enquiry response notification:', error);
    throw error;
  }
};

/**
 * Send welcome notification to new users
 * @param {Object} userData - User data
 * @returns {Promise<Object>} Send result
 */
const sendWelcomeNotification = async (userData) => {
  try {
    const { name, email, phone } = userData;

    const results = {
      email: { sent: false, error: null },
      sms: { sent: false, error: null }
    };

    // Send welcome email
    try {
      const emailTemplate = additionalEmailTemplates.userWelcome({ name });

      await sendEmail({
        to: email,
        subject: emailTemplate.subject,
        html: emailTemplate.html
      });
      results.email.sent = true;
    } catch (error) {
      results.email.error = error.message;
    }

    // Send welcome SMS
    try {
      await sendSMS({
        to: phone,
        body: `Welcome to ${process.env.COMPANY_NAME || 'Real Estate Platform'}, ${name}! Start exploring properties at ${process.env.FRONTEND_URL}`
      });
      results.sms.sent = true;
    } catch (error) {
      results.sms.error = error.message;
    }

    return results;

  } catch (error) {
    console.error('Error sending welcome notification:', error);
    throw error;
  }
};

/**
 * Send property alert to interested users
 * @param {Array} users - List of users to notify
 * @param {Object} propertyData - Property data
 * @returns {Promise<Object>} Send results
 */
const sendPropertyAlert = async (users, propertyData) => {
  try {
    const {
      propertyTitle,
      price,
      location,
      bedrooms,
      area,
      slug
    } = propertyData;

    const results = {
      totalUsers: users.length,
      emailsSent: 0,
      smsSent: 0,
      errors: []
    };

    for (const user of users) {
      try {
        // Send email alert
        await sendEmail({
          to: user.email,
          subject: `New Property Alert - ${propertyTitle}`,
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
              <h2 style="color: #2c3e50;">New Property Alert</h2>
              
              <p>Hi ${user.name},</p>
              
              <p>A new property matching your preferences is now available:</p>
              
              <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h3>${propertyTitle}</h3>
                <p><strong>Price:</strong> ₹${price.toLocaleString()}</p>
                <p><strong>Location:</strong> ${location}</p>
                ${bedrooms ? `<p><strong>Bedrooms:</strong> ${bedrooms}</p>` : ''}
                <p><strong>Area:</strong> ${area} sq.ft</p>
              </div>
              
              <div style="text-align: center; margin: 30px 0;">
                <a href="${process.env.FRONTEND_URL}/properties/${slug}" 
                   style="background: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                  View Property
                </a>
              </div>
            </div>
          `
        });
        results.emailsSent++;

        // Send SMS alert if user has phone
        if (user.phone) {
          const smsBody = additionalSmsTemplates.propertyAlert({
            propertyTitle,
            price,
            location,
            bedrooms,
            area,
            slug
          });

          await sendSMS({
            to: user.phone,
            body: smsBody
          });
          results.smsSent++;
        }

      } catch (error) {
        results.errors.push({
          user: user.email,
          error: error.message
        });
      }
    }

    return results;

  } catch (error) {
    console.error('Error sending property alerts:', error);
    throw error;
  }
};


// ================================================================
// AGENT NOTIFICATION FUNCTIONS
// ================================================================

/**
 * Send agent account creation notifications
 * @param {Object} data - Notification data
 * @returns {Promise<Object>} Notification results
 */
const sendAgentAccountNotifications = async (data) => {
  const {
    agentId,
    adminId,
    agent,
    tempPassword,
    emailToken,
    phoneCode,
    connection
  } = data;

  const results = {
    email: { sent: false, error: null, messageId: null },
    sms: { sent: false, error: null, messageId: null }
  };

  // Prepare email data
  const emailData = {
    name: agent.name,
    email: agent.email,
    tempPassword,
    phoneCode,
    emailToken,
    licenseNumber: agent.license_number,
    agencyName: agent.agency_name,
    commissionRate: agent.commission_rate,
    experienceYears: agent.experience_years
  };

  const emailTemplate = emailTemplates.agentAccountCreated(emailData);

  // Send email notification
  try {
    const emailResult = await sendEmail({
      to: agent.email,
      subject: emailTemplate.subject,
      html: emailTemplate.html
    });

    results.email.sent = true;
    results.email.messageId = emailResult.messageId;

  } catch (error) {
    console.error('Failed to send agent creation email:', error);
    results.email.error = error.message;
  }

  // Send SMS notification
  try {
    const smsBody = smsTemplates.agentAccountCreated({
      name: agent.name,
      email: agent.email,
      tempPassword,
      phoneCode
    });

    const smsResult = await sendSMS({
      to: agent.phone,
      body: smsBody
    });

    results.sms.sent = true;
    results.sms.messageId = smsResult.messageId;

  } catch (error) {
    console.error('Failed to send agent creation SMS:', error);
    results.sms.error = error.message;
  }

  // Store notification record in database
  try {
    await connection.execute(`
      INSERT INTO admin_created_notifications (
        user_id, created_by_admin_id, temp_password, 
        email_sent, sms_sent, email_sent_at, sms_sent_at,
        email_subject, email_body, sms_message
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      agentId,
      adminId,
      await hashPassword(tempPassword), // Store encrypted temp password
      results.email.sent,
      results.sms.sent,
      results.email.sent ? new Date() : null,
      results.sms.sent ? new Date() : null,
      emailTemplate.subject,
      results.email.sent ? 'Email sent successfully' : results.email.error,
      results.sms.sent ? 'SMS sent successfully' : results.sms.error
    ]);

  } catch (dbError) {
    console.error('Failed to store notification record:', dbError);
  }

  return results;
};

/**
 * Resend agent notifications
 * @param {number} agentId - Agent ID
 * @param {number} adminId - Admin ID
 * @returns {Promise<Object>} Resend results
 */
const resendAgentNotifications = async (agentId, adminId) => {
  return await executeTransaction(async (connection) => {
    try {
      // Verify agent exists and was created by admin
      const [agentCheck] = await connection.execute(`
        SELECT u.*, n.id as notification_id
        FROM users u
        JOIN admin_created_notifications n ON u.id = n.user_id
        WHERE u.id = ? AND n.created_by_admin_id = ? AND u.user_type = 'agent'
      `, [agentId, adminId]);

      if (agentCheck.length === 0) {
        throw new NotFoundError('Agent not found or not created by you');
      }

      const agent = agentCheck[0];

      // Generate new credentials
      const tempPassword = generateSecurePassword(12);
      const hashedPassword = await hashPassword(tempPassword);
      const emailToken = generateVerificationToken();
      const phoneCode = generateVerificationCode(6);

      // Update agent password and tokens
      await connection.execute(`
        UPDATE users SET 
          password = ?, 
          email_verification_token = ?, 
          phone_verification_code = ?,
          updated_at = NOW()
        WHERE id = ?
      `, [hashedPassword, emailToken, phoneCode, agentId]);

      // Send notifications
      const notificationResult = await sendAgentAccountNotifications({
        agentId,
        adminId,
        agent,
        tempPassword,
        emailToken,
        phoneCode,
        connection
      });

      // Update notification record
      await connection.execute(`
        UPDATE admin_created_notifications SET
          email_sent = ?,
          sms_sent = ?,
          email_sent_at = ?,
          sms_sent_at = ?,
          updated_at = NOW()
        WHERE id = ?
      `, [
        notificationResult.email.sent,
        notificationResult.sms.sent,
        notificationResult.email.sent ? new Date() : null,
        notificationResult.sms.sent ? new Date() : null,
        agent.notification_id
      ]);

      logDatabaseOperation('agent_notifications_resent', {
        agentId,
        adminId,
        emailSent: notificationResult.email.sent,
        smsSent: notificationResult.sms.sent
      });

      return {
        ...notificationResult,
        tempPassword, // Include for admin reference
        newTokens: {
          emailToken,
          phoneCode
        }
      };

    } catch (error) {
      console.error('Error resending agent notifications:', error);
      throw handleDatabaseError(error);
    }
  });
};

/**
 * Get agent notification status
 * @param {number} agentId - Agent ID
 * @param {number} adminId - Admin ID
 * @returns {Promise<Object>} Notification status
 */
const getAgentNotificationStatus = async (agentId, adminId) => {
  try {
    const [notifications] = await executeQuery(`
      SELECT 
        n.*,
        u.name as agent_name,
        u.email as agent_email,
        u.phone as agent_phone,
        u.email_verified_at,
        u.phone_verified_at,
        u.last_login_at
      FROM admin_created_notifications n
      JOIN users u ON n.user_id = u.id
      WHERE n.user_id = ? AND n.created_by_admin_id = ?
      ORDER BY n.created_at DESC
      LIMIT 1
    `, [agentId, adminId]);

    if (notifications.length === 0) {
      throw new NotFoundError('Notification record not found');
    }

    const notification = notifications[0];

    return {
      ...notification,
      verification_status: {
        email_verified: !!notification.email_verified_at,
        phone_verified: !!notification.phone_verified_at,
        fully_verified: !!(notification.email_verified_at && notification.phone_verified_at)
      },
      login_status: {
        has_logged_in: !!notification.last_login_at,
        last_login_at: notification.last_login_at,
        password_reset_required: !!notification.password_reset_required
      }
    };

  } catch (error) {
    console.error('Error fetching agent notification status:', error);
    throw handleDatabaseError(error);
  }
};

// ================================================================
// VERIFICATION NOTIFICATION FUNCTIONS
// ================================================================

/**
 * Send email verification
 * @param {number} userId - User ID
 * @param {number} adminId - Admin ID (optional)
 * @returns {Promise<Object>} Send result
 */
const sendVerificationEmail = async (userId, adminId = null) => {
  try {
    // Get user details
    const [users] = await executeQuery(
      'SELECT id, name, email FROM users WHERE id = ?',
      [userId]
    );

    if (users.length === 0) {
      throw new NotFoundError('User not found');
    }

    const user = users[0];

    // Generate new verification token
    const token = generateVerificationToken();

    // Update user with new token
    await executeQuery(
      'UPDATE users SET email_verification_token = ?, updated_at = NOW() WHERE id = ?',
      [token, userId]
    );

    // Send verification email
    const emailTemplate = emailTemplates.emailVerification({
      name: user.name,
      token
    });

    const result = await sendEmail({
      to: user.email,
      subject: emailTemplate.subject,
      html: emailTemplate.html
    });

    logDatabaseOperation('verification_email_sent', {
      userId,
      adminId,
      email: user.email
    });

    return {
      success: true,
      email: user.email,
      sentAt: result.sentAt
    };

  } catch (error) {
    console.error('Error sending verification email:', error);
    throw handleDatabaseError(error);
  }
};

/**
 * Send SMS verification
 * @param {number} userId - User ID
 * @param {number} adminId - Admin ID (optional)
 * @returns {Promise<Object>} Send result
 */
const sendVerificationSMS = async (userId, adminId = null) => {
  try {
    // Get user details
    const [users] = await executeQuery(
      'SELECT id, name, phone FROM users WHERE id = ?',
      [userId]
    );

    if (users.length === 0) {
      throw new NotFoundError('User not found');
    }

    const user = users[0];

    // Generate new verification code
    const code = generateVerificationCode(6);

    // Update user with new code
    await executeQuery(
      'UPDATE users SET phone_verification_code = ?, updated_at = NOW() WHERE id = ?',
      [code, userId]
    );

    // Send verification SMS
    const smsBody = smsTemplates.phoneVerification({ code });

    const result = await sendSMS({
      to: user.phone,
      body: smsBody
    });

    logDatabaseOperation('verification_sms_sent', {
      userId,
      adminId,
      phone: user.phone
    });

    return {
      success: true,
      phone: user.phone,
      sentAt: result.sentAt
    };

  } catch (error) {
    console.error('Error sending verification SMS:', error);
    throw handleDatabaseError(error);
  }
};

// ================================================================
// ENQUIRY NOTIFICATION FUNCTIONS
// ================================================================

/**
 * Send enquiry notification to agent
 * @param {Object} enquiryData - Enquiry data
 * @returns {Promise<Object>} Send result
 */
const sendEnquiryNotification = async (enquiryData) => {
  try {
    const {
      agentId,
      agentEmail,
      agentPhone,
      clientName,
      clientPhone,
      propertyTitle,
      enquiryId
    } = enquiryData;

    const results = {
      email: { sent: false, error: null },
      sms: { sent: false, error: null }
    };

    // Send email notification
    try {
      await sendEmail({
        to: agentEmail,
        subject: 'New Property Enquiry Assigned',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #2c3e50;">New Enquiry Assigned</h2>
            <p>A new property enquiry has been assigned to you:</p>
            
            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <h3>Enquiry Details</h3>
              <p><strong>Client:</strong> ${clientName}</p>
              <p><strong>Property:</strong> ${propertyTitle}</p>
              <p><strong>Client Phone:</strong> ${clientPhone}</p>
              <p><strong>Enquiry ID:</strong> #${enquiryId}</p>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${process.env.FRONTEND_URL}/agent/enquiries/${enquiryId}" 
                 style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                View Enquiry Details
              </a>
            </div>
          </div>
        `
      });
      results.email.sent = true;
    } catch (error) {
      results.email.error = error.message;
    }

    // Send SMS notification
    try {
      const smsBody = smsTemplates.enquiryNotification({
        clientName,
        propertyTitle,
        clientPhone
      });

      await sendSMS({
        to: agentPhone,
        body: smsBody
      });
      results.sms.sent = true;
    } catch (error) {
      results.sms.error = error.message;
    }

    return results;

  } catch (error) {
    console.error('Error sending enquiry notification:', error);
    throw handleDatabaseError(error);
  }
};

// ================================================================
// BULK NOTIFICATION FUNCTIONS
// ================================================================

/**
 * Send bulk notifications
 * @param {Array} recipients - List of recipients
 * @param {Object} messageData - Message data
 * @param {string} type - Notification type ('email' or 'sms')
 * @returns {Promise<Object>} Bulk send results
 */
const sendBulkNotifications = async (recipients, messageData, type = 'email') => {
  const results = {
    total: recipients.length,
    successful: 0,
    failed: 0,
    errors: []
  };

  for (const recipient of recipients) {
    try {
      if (type === 'email') {
        await sendEmail({
          to: recipient.email,
          subject: messageData.subject,
          html: messageData.html
        });
      } else if (type === 'sms') {
        await sendSMS({
          to: recipient.phone,
          body: messageData.body
        });
      }
      
      results.successful++;
      
    } catch (error) {
      results.failed++;
      results.errors.push({
        recipient: recipient.email || recipient.phone,
        error: error.message
      });
    }
  }

  logDatabaseOperation('bulk_notifications_sent', {
    type,
    total: results.total,
    successful: results.successful,
    failed: results.failed
  });

  return results;
};

// ================================================================
// EXPORTS
// ================================================================

module.exports = {
  // Core functions
  sendEmail,
  sendSMS,
  
  // Agent notifications
  sendAgentAccountNotifications,
  resendAgentNotifications,
  getAgentNotificationStatus,
  
  // Verification notifications
  sendVerificationEmail,
  sendVerificationSMS,
  
  // Enquiry notifications
  sendEnquiryNotification,
  
  // Bulk notifications
  sendBulkNotifications,
  
  // Additional functions
  sendPropertyStatusNotification,
  sendEnquiryResponseNotification,
  sendWelcomeNotification,
  sendPropertyAlert,

  // Templates
  emailTemplates,
  smsTemplates,
  additionalEmailTemplates,
  additionalSmsTemplates
};