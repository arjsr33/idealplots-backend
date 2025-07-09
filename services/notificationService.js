// ================================================================
// BACKEND/SERVICES/NOTIFICATIONSERVICE.JS - MAIN NOTIFICATION SERVICE
// Complete notification service orchestrating email and SMS services
// ================================================================

const { 
  executeQuery, 
  executeTransaction,
  handleDatabaseError,
  logDatabaseOperation
} = require('../database/connection');

const { 
  hashPassword,
  generateVerificationToken,
  generateVerificationCode,
  generateSecurePassword
} = require('../middleware/auth');

const {
  ValidationError,
  NotFoundError,
  ExternalServiceError
} = require('../middleware/errorHandler');

// Import specialized services
const emailService = require('./emailService');
const smsService = require('./smsService');

// ================================================================
// RE-EXPORT CORE FUNCTIONS
// ================================================================

const { sendEmail, sendBulkEmails, emailTemplates } = emailService;
const { sendSMS, sendOTPSMS, sendBulkSMS, checkSMSStatus, smsTemplates } = smsService;

// ================================================================
// HIGH-LEVEL NOTIFICATION FUNCTIONS
// ================================================================

/**
 * Send property status update notification
 * @param {Object} data - Property and status data
 * @returns {Promise<Object>} Send result
 */
const sendPropertyStatusNotification = async (data) => {
  try {
    const { ownerEmail, ownerPhone, ownerName, propertyTitle, status, notes, propertySlug } = data;

    const results = {
      email: { sent: false, error: null },
      sms: { sent: false, error: null }
    };

    // Send email notification
    try {
      const emailTemplate = emailTemplates.propertyStatusUpdate({
        ownerName, propertyTitle, status, notes, propertySlug
      });

      const emailResult = await sendEmail({
        to: ownerEmail,
        subject: emailTemplate.subject,
        html: emailTemplate.html
      });
      results.email.sent = emailResult.success;
      if (!emailResult.success) {
        results.email.error = emailResult.error;
      }
    } catch (error) {
      results.email.error = error.message;
    }

    // Send SMS notification
    if (ownerPhone) {
      try {
        const smsBody = smsTemplates.propertyStatusUpdate({ propertyTitle, status, notes });
        const smsResult = await sendSMS({ to: ownerPhone, body: smsBody });
        results.sms.sent = smsResult.success;
        if (!smsResult.success) {
          results.sms.error = smsResult.error;
        }
      } catch (error) {
        results.sms.error = error.message;
      }
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
    const { clientEmail, clientPhone, clientName, ticketNumber, status, agentName, notes } = data;

    const results = {
      email: { sent: false, error: null },
      sms: { sent: false, error: null }
    };

    // Send email notification
    try {
      const emailTemplate = emailTemplates.enquiryUpdate({
        clientName, ticketNumber, status, agentName, notes
      });

      const emailResult = await sendEmail({
        to: clientEmail,
        subject: emailTemplate.subject,
        html: emailTemplate.html
      });
      results.email.sent = emailResult.success;
      if (!emailResult.success) {
        results.email.error = emailResult.error;
      }
    } catch (error) {
      results.email.error = error.message;
    }

    // Send SMS notification
    if (clientPhone) {
      try {
        const smsBody = smsTemplates.enquiryResponse({ ticketNumber, status, agentName, notes });
        const smsResult = await sendSMS({ to: clientPhone, body: smsBody });
        results.sms.sent = smsResult.success;
        if (!smsResult.success) {
          results.sms.error = smsResult.error;
        }
      } catch (error) {
        results.sms.error = error.message;
      }
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
      const emailTemplate = emailTemplates.userWelcome({ name });
      const emailResult = await sendEmail({
        to: email,
        subject: emailTemplate.subject,
        html: emailTemplate.html
      });
      results.email.sent = emailResult.success;
      if (!emailResult.success) {
        results.email.error = emailResult.error;
      }
    } catch (error) {
      results.email.error = error.message;
    }

    // Send welcome SMS
    if (phone) {
      try {
        const smsBody = smsTemplates.welcomeUser({ name });
        const smsResult = await sendSMS({ to: phone, body: smsBody });
        results.sms.sent = smsResult.success;
        if (!smsResult.success) {
          results.sms.error = smsResult.error;
        }
      } catch (error) {
        results.sms.error = error.message;
      }
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
    const { propertyTitle, price, location, bedrooms, area, slug } = propertyData;

    const results = {
      totalUsers: users.length,
      emailsSent: 0,
      smsSent: 0,
      errors: []
    };

    for (const user of users) {
      try {
        // Send email alert
        const emailTemplate = emailTemplates.propertyAlert({
          propertyTitle, price, location, bedrooms, area, slug
        });

        const emailResult = await sendEmail({
          to: user.email,
          subject: emailTemplate.subject,
          html: emailTemplate.html
        });

        if (emailResult.success) {
          results.emailsSent++;
        }

        // Send SMS alert if user has phone
        if (user.phone) {
          const smsBody = smsTemplates.propertyAlert({
            propertyTitle, price, location, bedrooms, area, slug
          });

          const smsResult = await sendSMS({ to: user.phone, body: smsBody });
          if (smsResult.success) {
            results.smsSent++;
          }
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
  const { agentId, adminId, agent, tempPassword, emailToken, phoneCode, connection } = data;

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

    results.email.sent = emailResult.success;
    results.email.messageId = emailResult.messageId;
    if (!emailResult.success) {
      results.email.error = emailResult.error;
    }
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

    const smsResult = await sendSMS({ to: agent.phone, body: smsBody });
    results.sms.sent = smsResult.success;
    results.sms.messageId = smsResult.messageId;
    if (!smsResult.success) {
      results.sms.error = smsResult.error;
    }
  } catch (error) {
    console.error('Failed to send agent creation SMS:', error);
    results.sms.error = error.message;
  }

  // Store notification record in database
  if (connection) {
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
        await hashPassword(tempPassword),
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
  }

  return results;
};

/**
 * Resend agent notifications (RESTORED MISSING FUNCTION)
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

      if (logDatabaseOperation) {
        logDatabaseOperation('agent_notifications_resent', {
          agentId,
          adminId,
          emailSent: notificationResult.email.sent,
          smsSent: notificationResult.sms.sent
        });
      }

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
      throw handleDatabaseError ? handleDatabaseError(error) : error;
    }
  });
};

/**
 * Get agent notification status (RESTORED MISSING FUNCTION)
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
    throw handleDatabaseError ? handleDatabaseError(error) : error;
  }
};

/**
 * Send enquiry notification to agent
 * @param {Object} enquiryData - Enquiry data
 * @returns {Promise<Object>} Send result
 */
const sendEnquiryNotification = async (enquiryData) => {
  try {
    const {
      agentId, agentEmail, agentPhone, agentName,
      clientName, clientPhone, propertyTitle,
      enquiryId, ticketNumber, requirements
    } = enquiryData;

    const results = {
      email: { sent: false, error: null },
      sms: { sent: false, error: null }
    };

    // Send email notification
    try {
      const emailTemplate = emailTemplates.agentEnquiryAssignment({
        agentName, ticketNumber, requirements, clientPhone
      });

      const emailResult = await sendEmail({
        to: agentEmail,
        subject: emailTemplate.subject,
        html: emailTemplate.html
      });

      results.email.sent = emailResult.success;
      if (!emailResult.success) {
        results.email.error = emailResult.error;
      }
    } catch (error) {
      results.email.error = error.message;
    }

    // Send SMS notification
    if (agentPhone) {
      try {
        const smsBody = smsTemplates.enquiryNotification({
          clientName, propertyTitle, clientPhone
        });

        const smsResult = await sendSMS({ to: agentPhone, body: smsBody });
        results.sms.sent = smsResult.success;
        if (!smsResult.success) {
          results.sms.error = smsResult.error;
        }
      } catch (error) {
        results.sms.error = error.message;
      }
    }

    return results;
  } catch (error) {
    console.error('Error sending enquiry notification:', error);
    throw handleDatabaseError ? handleDatabaseError(error) : error;
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
    const [users] = await executeQuery(
      'SELECT id, name, email FROM users WHERE id = ?',
      [userId]
    );

    if (users.length === 0) {
      throw new NotFoundError('User not found');
    }

    const user = users[0];
    const token = generateVerificationToken();

    await executeQuery(
      'UPDATE users SET email_verification_token = ?, updated_at = NOW() WHERE id = ?',
      [token, userId]
    );

    const emailTemplate = emailTemplates.emailVerification({
      name: user.name,
      token
    });

    const result = await sendEmail({
      to: user.email,
      subject: emailTemplate.subject,
      html: emailTemplate.html
    });

    if (logDatabaseOperation) {
      logDatabaseOperation('verification_email_sent', {
        userId, adminId, email: user.email
      });
    }

    return {
      success: result.success,
      email: user.email,
      sentAt: result.sentAt,
      error: result.error || null
    };
  } catch (error) {
    console.error('Error sending verification email:', error);
    throw handleDatabaseError ? handleDatabaseError(error) : error;
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
    const [users] = await executeQuery(
      'SELECT id, name, phone FROM users WHERE id = ?',
      [userId]
    );

    if (users.length === 0) {
      throw new NotFoundError('User not found');
    }

    const user = users[0];
    const code = generateVerificationCode(6);

    await executeQuery(
      'UPDATE users SET phone_verification_code = ?, updated_at = NOW() WHERE id = ?',
      [code, userId]
    );

    const smsBody = smsTemplates.phoneVerification({ code });
    const result = await sendSMS({ to: user.phone, body: smsBody });

    if (logDatabaseOperation) {
      logDatabaseOperation('verification_sms_sent', {
        userId, adminId, phone: user.phone
      });
    }

    return {
      success: result.success,
      phone: user.phone,
      sentAt: result.sentAt,
      error: result.error || null
    };
  } catch (error) {
    console.error('Error sending verification SMS:', error);
    throw handleDatabaseError ? handleDatabaseError(error) : error;
  }
};
/**
 * Send password reset notification (email + optional SMS)
 * @param {number} userId - User ID
 * @returns {Promise<Object>} Send results
 */
const sendPasswordResetNotification = async (userId) => {
  try {
    const [users] = await executeQuery(
      'SELECT id, name, email, phone FROM users WHERE id = ?',
      [userId]
    );

    if (users.length === 0) {
      throw new NotFoundError('User not found');
    }

    const user = users[0];
    const token = generateVerificationToken();
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

    // Store token with expiration (1 hour)
    await executeQuery(
      `UPDATE users 
       SET password_reset_token = ?, 
           password_reset_expires_at = DATE_ADD(NOW(), INTERVAL 1 HOUR)
       WHERE id = ?`,
      [token, userId]
    );

    const results = {
      email: { sent: false, error: null },
      sms: { sent: false, error: null },
      token // For debugging/logging
    };

    // Send email
    try {
      const emailResult = await emailService.sendPasswordResetEmail(
        user.email, 
        user.name, 
        token
      );
      results.email.sent = emailResult.success;
      if (!emailResult.success) {
        results.email.error = emailResult.error;
      }
    } catch (error) {
      results.email.error = error.message;
    }

    // Optionally send SMS if phone exists
    // In sendPasswordResetNotification function:
  if (user.phone) {
    try {
      const smsBody = smsTemplates.passwordReset({
        name: user.name,
        code: code,       // The verification code (if using OTP)
        token: token      // The reset token (if using link)
      });
      const smsResult = await sendSMS({
        to: user.phone,
        body: smsBody
      });
      results.sms.sent = smsResult.success;
      if (!smsResult.success) {
        results.sms.error = smsResult.error;
      }
    } catch (error) {
      results.sms.error = error.message;
    }
    }

    return results;
  } catch (error) {
    console.error('Error sending password reset notification:', error);
    throw handleDatabaseError ? handleDatabaseError(error) : error;
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
  let results;

  if (type === 'email') {
    results = await sendBulkEmails(recipients, messageData);
  } else if (type === 'sms') {
    results = await sendBulkSMS(recipients, messageData);
  } else {
    throw new ValidationError('Invalid notification type. Must be "email" or "sms"');
  }

  if (logDatabaseOperation) {
    logDatabaseOperation('bulk_notifications_sent', {
      type,
      total: results.total,
      successful: results.successful,
      failed: results.failed
    });
  }

  return results;
};

// ================================================================
// UTILITY FUNCTIONS
// ================================================================

/**
 * Get notification service health status
 * @returns {Object} Service health status
 */
const getServiceHealth = () => {
  return {
    email: {
      configured: !!emailService.emailTransporter,
      provider: 'SMTP'
    },
    sms: {
      configured: !!smsService.MSG91_CONFIG.authKey,
      provider: 'MSG91'
    },
    timestamp: new Date().toISOString()
  };
};

/**
 * Test notification services
 * @param {Object} testData - Test data
 * @returns {Promise<Object>} Test results
 */
const testNotificationServices = async (testData) => {
  const { testEmail, testPhone } = testData;
  const results = {
    email: { success: false, error: null },
    sms: { success: false, error: null }
  };

  // Test email service
  if (testEmail) {
    try {
      const emailResult = await sendEmail({
        to: testEmail,
        subject: 'Test Email - Notification Service',
        html: '<p>This is a test email from the notification service.</p>'
      });
      results.email.success = emailResult.success;
      if (!emailResult.success) {
        results.email.error = emailResult.error;
      }
    } catch (error) {
      results.email.error = error.message;
    }
  }

  // Test SMS service
  if (testPhone) {
    try {
      const smsResult = await sendSMS({
        to: testPhone,
        body: 'Test SMS from notification service'
      });
      results.sms.success = smsResult.success;
      if (!smsResult.success) {
        results.sms.error = smsResult.error;
      }
    } catch (error) {
      results.sms.error = error.message;
    }
  }

  return results;
};

// ================================================================
// TEMPLATE BUILDER UTILITIES
// ================================================================

/**
 * Build custom email template
 * @param {Object} templateData - Template data
 * @returns {Object} Email template
 */
const buildCustomEmailTemplate = (templateData) => {
  const { subject, title, message, buttonText, buttonUrl, footerText } = templateData;
  
  return {
    subject,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2c3e50;">${process.env.COMPANY_NAME || 'Ideal Plots'}</h1>
        </div>
        
        <div style="background: #f8f9fa; padding: 25px; border-radius: 8px; margin: 20px 0;">
          <h2 style="color: #495057; margin-top: 0;">${title}</h2>
          <p style="color: #212529; line-height: 1.6;">${message}</p>
        </div>
        
        ${buttonText && buttonUrl ? `
          <div style="text-align: center; margin: 30px 0;">
            <a href="${buttonUrl}" 
               style="background: #007bff; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
              ${buttonText}
            </a>
          </div>
        ` : ''}
        
        <div style="text-align: center; color: #6c757d; font-size: 14px; margin-top: 30px;">
          <p>${footerText || `Best regards,<br><strong>${process.env.COMPANY_NAME || 'Ideal Plots'}</strong>`}</p>
        </div>
      </div>
    `
  };
};

/**
 * Build custom SMS template
 * @param {Object} templateData - Template data
 * @returns {string} SMS message
 */
const buildCustomSMSTemplate = (templateData) => {
  const { message, companyName = process.env.COMPANY_NAME || 'Ideal Plots', url } = templateData;
  
  let smsText = `${message} - ${companyName}`;
  
  if (url) {
    smsText += ` ${url}`;
  }
  
  return smsText.trim();
};

// ================================================================
// EXPORTS
// ================================================================

module.exports = {
  // Core functions (re-exported from specialized services)
  sendEmail,
  sendSMS,
  sendOTPSMS,
  checkSMSStatus,

  // High-level notification functions
  sendPropertyStatusNotification,
  sendEnquiryResponseNotification,
  sendWelcomeNotification,
  sendPropertyAlert,

  // Agent notifications
  sendAgentAccountNotifications,
  resendAgentNotifications,        // RESTORED
  getAgentNotificationStatus,      // RESTORED

  // Verification notifications
  sendVerificationEmail,
  sendVerificationSMS,
  sendPasswordResetNotification,

  // Enquiry notifications
  sendEnquiryNotification,

  // Bulk notifications
  sendBulkNotifications,
  sendBulkEmails,
  sendBulkSMS,

  // Templates
  emailTemplates,
  smsTemplates,

  // Utilities
  getServiceHealth,
  testNotificationServices,
  buildCustomEmailTemplate,
  buildCustomSMSTemplate,

  // Access to specialized services
  emailService,
  smsService
};