const Module = require('node:module');
const originalLoad = Module._load;
Module._load = function mockTripletex(request, parent, isMain) {
  if (request === './tripletexClient' && parent?.filename?.endsWith('/server.js')) {
    return {
      syncMembershipToTripletex: async () => { throw new Error('Unexpected Tripletex write'); },
      approveSubscriptionInvoice: async () => { throw new Error('Unexpected Tripletex write'); },
      stopTripletexSubscriptionForOrder: async () => { throw new Error('Unexpected Tripletex write'); },
      listMembershipInvoices: async () => [{
        id: 1, invoiceNumber: 123, orders: [{ id: 411 }], invoiceDueDate: '2026-10-01',
        amount: 449, amountOutstanding: 449, isCreditNote: false,
        isCredited: false, isCharged: true,
      }],
    };
  }
  return originalLoad.call(this, request, parent, isMain);
};
