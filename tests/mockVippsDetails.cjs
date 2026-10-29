const axios = require('axios');

axios.post = async url => {
  if (url.endsWith('/accesstoken/get')) return { data: { access_token: 'synthetic-token' } };
  throw new Error(`Unexpected POST in synthetic test: ${url}`);
};

axios.get = async url => {
  const match = url.match(/\/ecomm\/v2\/payments\/([^/]+)\/details$/);
  if (!match) throw new Error(`Unexpected GET in synthetic test: ${url}`);
  return {
    data: {
      orderId: decodeURIComponent(match[1]),
      transactionSummary: { capturedAmount: 100, refundedAmount: 0 },
      transactionLogHistory: [{
        operation: 'SALE', operationSuccess: true, amount: 100,
        timeStamp: '2026-10-29T12:00:00Z',
      }],
    },
  };
};
