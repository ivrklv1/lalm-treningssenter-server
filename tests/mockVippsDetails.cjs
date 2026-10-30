const axios = require('axios');

axios.post = async url => {
  if (url.endsWith('/accesstoken/get')) return { data: { access_token: 'synthetic-token' } };
  if (url.endsWith('/capture')) return { status: 500, data: { error: 'synthetic capture failure' } };
  throw new Error(`Unexpected POST in synthetic test: ${url}`);
};

axios.get = async url => {
  const match = url.match(/\/ecomm\/v2\/payments\/([^/]+)\/details$/);
  if (!match) throw new Error(`Unexpected GET in synthetic test: ${url}`);
  if (process.env.MOCK_VIPPS_DETAILS_ERROR === 'true') throw new Error('Synthetic Vipps lookup failed');
  const operation = process.env.MOCK_VIPPS_OPERATION || 'SALE';
  const paid = operation === 'SALE' || operation === 'CAPTURE';
  const refundedAmount = Number(process.env.MOCK_VIPPS_REFUNDED_AMOUNT || 0);
  return {
    data: {
      orderId: decodeURIComponent(match[1]),
      transactionSummary: { capturedAmount: paid ? 100 : 0, refundedAmount },
      transactionLogHistory: [{
        operation, operationSuccess: true, amount: 100,
        timeStamp: '2026-10-29T12:00:00Z',
      }, ...(refundedAmount ? [{ operation: 'REFUND', operationSuccess: true, amount: refundedAmount, timeStamp: '2026-10-30T12:00:00Z' }] : [])],
    },
  };
};
