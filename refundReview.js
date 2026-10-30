function confirmedRefund(details, order) {
  if (!details || details.orderId !== order?.orderId) {
    throw new Error('vipps_order_mismatch');
  }
  const capturedAmount = Number(details.transactionSummary?.capturedAmount);
  const refundedAmount = Number(details.transactionSummary?.refundedAmount);
  if (!Number.isSafeInteger(capturedAmount) || capturedAmount <= 0 ||
      capturedAmount < Number(order.amount) ||
      !Number.isSafeInteger(refundedAmount) || refundedAmount < 0 ||
      refundedAmount > capturedAmount) {
    throw new Error('vipps_refund_summary_invalid');
  }
  if (refundedAmount === 0) return null;
  if (!Array.isArray(details.transactionLogHistory)) throw new Error('vipps_refund_log_missing');
  const refunds = details.transactionLogHistory.filter(entry =>
    entry?.operationSuccess === true &&
    String(entry.operation).toUpperCase() === 'REFUND' &&
    Number.isSafeInteger(Number(entry.amount)) && Number(entry.amount) > 0 &&
    Number.isFinite(Date.parse(entry.timeStamp))
  );
  if (!refunds.length) throw new Error('vipps_refund_unverified');
  if (refunds.reduce((sum, entry) => sum + Number(entry.amount), 0) < refundedAmount) {
    throw new Error('vipps_refund_amount_unverified');
  }
  refunds.sort((a, b) => Date.parse(b.timeStamp) - Date.parse(a.timeStamp));
  return {
    capturedAmount,
    refundedAmount,
    kind: refundedAmount === capturedAmount ? 'full' : 'partial',
    lastRefundAt: refunds[0].timeStamp,
  };
}

module.exports = { confirmedRefund };
