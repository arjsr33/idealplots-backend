// ================================================================
// BACKEND/SERVICES/SMSSERVICE.JS - SMS HANDLING MODULE
// Dedicated SMS service with MSG91 integration and templates
// ================================================================

const axios = require('axios');
const { logDatabaseOperation } = require('../database/connection');
const { ExternalServiceError, ValidationError } = require('../middleware/errorHandler');

// ================================================================
// MSG91 SMS CONFIGURATION
// ================================================================

const MSG91_CONFIG = {
  authKey: process.env.MSG91_AUTH_KEY,
  senderId: process.env.MSG91_SENDER_ID || 'IDEALP',
  route: process.env.MSG91_ROUTE || '4',
  country: process.env.MSG91_COUNTRY || '91',
  otpTemplateId: process.env.MSG91_OTP_TEMPLATE_ID,
  generalTemplateId: process.env.MSG91_GENERAL_TEMPLATE_ID,
  baseUrl: 'https://api.msg91.com/api',
  otpUrl: 'https://control.msg91.com/api',
  flowUrl: 'https://api.msg91.com/api/v5/flow'
};

const msg91Configured = !!MSG91_CONFIG.authKey;

if (msg91Configured) {
  console.log('✅ MSG91 SMS service configured');
} else {
  console.warn('⚠️ MSG91 SMS service not configured - Auth key missing');
}

// ================================================================
// SMS TEMPLATES
// ================================================================

const smsTemplates = {
  agentAccountCreated: (data) => 
    `Welcome ${data.name}! Your agent account is ready at ${process.env.COMPANY_NAME || 'Ideal Plots'}. Login: ${data.email}, Password: ${data.tempPassword}, OTP: ${data.phoneCode}. Login: ${process.env.FRONTEND_URL}/agent/login. Change password on first login.`.trim(),

  phoneVerification: (data) => 
    `Your verification OTP for ${process.env.COMPANY_NAME || 'Ideal Plots'} is ${data.code}. Valid for 10 minutes. Do not share with anyone.`.trim(),

  passwordReset: (data) => 
    `Password reset requested for ${data.name}. Use code: ${data.code} or visit ${process.env.FRONTEND_URL}/reset-password?token=${data.token}. Code expires in 1 hour. Do not share this code.`.trim(),

  enquiryNotification: (data) => 
    `New enquiry assigned! Client: ${data.clientName}, Property: ${data.propertyTitle}, Contact: ${data.clientPhone}. Login to view: ${process.env.FRONTEND_URL}/agent/dashboard`.trim(),

  propertyStatusUpdate: (data) => 
    `Property Update: "${data.propertyTitle}" is now ${data.status.toUpperCase()}. ${data.status === 'approved' ? 'Congratulations! Your property is live.' : ''} View: ${process.env.FRONTEND_URL}/my-properties`.trim(),

  enquiryResponse: (data) => 
    `Enquiry ${data.ticketNumber} update: ${data.status}. ${data.agentName ? `Agent: ${data.agentName}. ` : ''}${data.notes ? `Message: ${data.notes}. ` : ''}Track: ${process.env.FRONTEND_URL}/track/${data.ticketNumber}`.trim(),

  propertyAlert: (data) => 
    `New property alert! ${data.propertyTitle} - ₹${data.price ? data.price.toLocaleString('en-IN') : 'Contact for Price'} at ${data.location}. ${data.bedrooms ? `${data.bedrooms}BHK ` : ''}${data.area}sq.ft. View: ${process.env.FRONTEND_URL}/properties/${data.slug}`.trim(),

  welcomeUser: (data) => 
    `Welcome to ${process.env.COMPANY_NAME || 'Ideal Plots'}, ${data.name}! Your account is ready. Start exploring properties: ${process.env.FRONTEND_URL}`.trim(),

  otpVerification: (data) => 
    `Your OTP for ${process.env.COMPANY_NAME || 'Ideal Plots'} verification is ${data.otp}. Valid for 10 minutes. Do not share this OTP with anyone.`.trim(),

  loginOTP: (data) => 
    `Your login OTP for ${process.env.COMPANY_NAME || 'Ideal Plots'} is ${data.otp}. Valid for 5 minutes. Do not share this OTP.`.trim()
};

// ================================================================
// UTILITY FUNCTIONS
// ================================================================

/**
 * Clean and validate Indian phone number
 * @param {string} phone - Phone number
 * @returns {string} Cleaned phone number
 */
const cleanPhoneNumber = (phone) => {
  if (!phone) {
    throw new ValidationError('Phone number is required');
  }

  // Remove +91 prefix and spaces
  const cleanPhone = phone.replace(/^\+91/, '').replace(/\s+/g, '');
  
  // Validate Indian phone number format (10 digits starting with 6-9)
  if (!/^[6-9]\d{9}$/.test(cleanPhone)) {
    throw new ValidationError('Invalid Indian phone number format');
  }

  return cleanPhone;
};

/**
 * Build MSG91 API URL
 * @param {string} endpoint - API endpoint
 * @returns {string} Full URL
 */
const buildApiUrl = (endpoint) => {
  switch (endpoint) {
    case 'flow':
      return MSG91_CONFIG.flowUrl;
    case 'sms':
      return `${MSG91_CONFIG.baseUrl}/sendhttp.php`;
    case 'status':
      return `${MSG91_CONFIG.baseUrl}/status.php`;
    case 'otp':
      return `${MSG91_CONFIG.otpUrl}/sendotp.php`;
    default:
      return `${MSG91_CONFIG.baseUrl}/${endpoint}`;
  }
};

// ================================================================
// MSG91 SMS FUNCTIONS
// ================================================================

/**
 * Send SMS via MSG91 Flow API (Template-based)
 * @param {Object} flowData - Flow data
 * @returns {Promise<Object>} Send result
 */
const sendFlowSMS = async (flowData) => {
  try {
    const { templateId, recipients } = flowData;

    if (!templateId || !recipients || !Array.isArray(recipients)) {
      throw new ValidationError('Template ID and recipients array are required for flow SMS');
    }

    const requestData = {
      template_id: templateId,
      short_url: '0',
      realTimeResponse: '1',
      recipients: recipients.map(recipient => ({
        mobiles: MSG91_CONFIG.country + cleanPhoneNumber(recipient.phone),
        ...recipient.variables
      }))
    };

    const response = await axios.post(buildApiUrl('flow'), requestData, {
      headers: {
        'authkey': MSG91_CONFIG.authKey,
        'Content-Type': 'application/json'
      },
      timeout: 15000
    });

    if (response.data && response.data.type === 'success') {
      return {
        success: true,
        messageId: response.data.request_id,
        status: 'sent',
        provider: 'MSG91_FLOW',
        sentAt: new Date().toISOString(),
        response: response.data
      };
    } else {
      throw new Error(response.data.message || 'MSG91 Flow API error');
    }

  } catch (error) {
    console.error('MSG91 Flow SMS failed:', error.response?.data || error.message);
    throw new ExternalServiceError(`Flow SMS sending failed: ${error.response?.data?.message || error.message}`);
  }
};

/**
 * Send SMS via MSG91 Direct API
 * @param {Object} smsData - SMS data
 * @returns {Promise<Object>} Send result
 */
const sendDirectSMS = async (smsData) => {
  try {
    const { to, message } = smsData;

    if (!to || !message) {
      throw new ValidationError('Phone number and message are required');
    }

    const cleanPhone = cleanPhoneNumber(to);

    const requestParams = {
      authkey: MSG91_CONFIG.authKey,
      mobiles: MSG91_CONFIG.country + cleanPhone,
      message: message,
      sender: MSG91_CONFIG.senderId,
      route: MSG91_CONFIG.route,
      response: 'json'
    };

    const response = await axios.post(buildApiUrl('sms'), null, {
      params: requestParams,
      timeout: 15000
    });

    // MSG91 direct API returns different response formats
    const responseData = response.data;
    const isSuccess = responseData.message === 'SMS sent successfully.' || 
                     responseData.type === 'success' ||
                     (responseData.message_id && !responseData.error);

    if (isSuccess) {
      if (logDatabaseOperation) {
        logDatabaseOperation('sms_sent', {
          to: cleanPhone,
          provider: 'MSG91_DIRECT',
          messageId: responseData.message_id || responseData.request_id,
          status: 'sent'
        });
      }

      return {
        success: true,
        messageId: responseData.message_id || responseData.request_id || Date.now().toString(),
        status: 'sent',
        provider: 'MSG91_DIRECT',
        sentAt: new Date().toISOString(),
        response: responseData
      };
    } else {
      throw new Error(responseData.message || responseData.error || 'MSG91 API error');
    }

  } catch (error) {
    console.error('MSG91 Direct SMS failed:', error.response?.data || error.message);
    throw new ExternalServiceError(`SMS sending failed: ${error.response?.data?.message || error.message}`);
  }
};

/**
 * Send OTP SMS via MSG91
 * @param {Object} otpData - OTP data
 * @returns {Promise<Object>} Send result
 */
const sendOTPSMS = async (otpData) => {
  try {
    const { phone, otp, companyName = process.env.COMPANY_NAME || 'Ideal Plots' } = otpData;

    if (!phone || !otp) {
      throw new ValidationError('Phone number and OTP are required');
    }

    // If OTP template is configured, use flow API
    if (MSG91_CONFIG.otpTemplateId) {
      return await sendFlowSMS({
        templateId: MSG91_CONFIG.otpTemplateId,
        recipients: [{
          phone: phone,
          variables: {
            OTP: otp,
            COMPANY: companyName
          }
        }]
      });
    } else {
      // Use direct SMS
      const message = smsTemplates.otpVerification({ otp });
      return await sendDirectSMS({ to: phone, message });
    }

  } catch (error) {
    console.error('OTP SMS sending failed:', error);
    throw error;
  }
};

/**
 * Main SMS sending function
 * @param {Object} smsData - SMS data
 * @returns {Promise<Object>} Send result
 */
const sendSMS = async (smsData) => {
  try {
    if (!msg91Configured) {
      throw new ExternalServiceError('MSG91 service not configured');
    }

    const { to, body, templateId, variables } = smsData;

    if (templateId && variables) {
      // Use template-based flow SMS
      return await sendFlowSMS({
        templateId,
        recipients: [{ phone: to, variables }]
      });
    } else {
      // Use direct SMS
      return await sendDirectSMS({ to, message: body });
    }

  } catch (error) {
    console.error('SMS sending failed:', error);
    throw error;
  }
};

/**
 * Check SMS delivery status
 * @param {string} messageId - MSG91 message ID
 * @returns {Promise<Object>} Delivery status
 */
const checkSMSStatus = async (messageId) => {
  try {
    if (!msg91Configured) {
      throw new ExternalServiceError('MSG91 service not configured');
    }

    if (!messageId) {
      throw new ValidationError('Message ID is required');
    }

    const response = await axios.get(buildApiUrl('status'), {
      params: {
        authkey: MSG91_CONFIG.authKey,
        message_id: messageId,
        response: 'json'
      },
      timeout: 10000
    });

    return {
      messageId,
      status: response.data.status || 'unknown',
      provider: 'MSG91',
      statusData: response.data,
      checkedAt: new Date().toISOString()
    };

  } catch (error) {
    console.error('MSG91 status check failed:', error.response?.data || error.message);
    throw new ExternalServiceError(`SMS status check failed: ${error.message}`);
  }
};

/**
 * Send bulk SMS
 * @param {Array} recipients - List of recipients
 * @param {Object} messageData - Message data
 * @returns {Promise<Object>} Bulk send results
 */
const sendBulkSMS = async (recipients, messageData) => {
  const results = {
    total: recipients.length,
    successful: 0,
    failed: 0,
    errors: []
  };

  // If template is provided, use flow API for bulk sending
  if (messageData.templateId) {
    try {
      const flowRecipients = recipients.map(recipient => ({
        phone: recipient.phone,
        variables: messageData.variables || {}
      }));

      const result = await sendFlowSMS({
        templateId: messageData.templateId,
        recipients: flowRecipients
      });

      if (result.success) {
        results.successful = recipients.length;
      } else {
        results.failed = recipients.length;
        results.errors.push({
          error: 'Bulk flow SMS failed'
        });
      }
    } catch (error) {
      results.failed = recipients.length;
      results.errors.push({
        error: error.message
      });
    }
  } else {
    // Send individual SMS for each recipient
    for (const recipient of recipients) {
      try {
        const smsResult = await sendDirectSMS({
          to: recipient.phone,
          message: messageData.body || messageData.message
        });

        if (smsResult.success) {
          results.successful++;
        } else {
          results.failed++;
          results.errors.push({
            recipient: recipient.phone,
            error: smsResult.error || 'Unknown error'
          });
        }
      } catch (error) {
        results.failed++;
        results.errors.push({
          recipient: recipient.phone,
          error: error.message
        });
      }
    }
  }

  if (logDatabaseOperation) {
    logDatabaseOperation('bulk_sms_sent', {
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
  sendSMS,
  sendDirectSMS,
  sendFlowSMS,
  sendOTPSMS,
  sendBulkSMS,
  checkSMSStatus,
  smsTemplates,
  cleanPhoneNumber,
  MSG91_CONFIG
};