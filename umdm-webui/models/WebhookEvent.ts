import mongoose from 'mongoose';

const WebhookEventSchema = new mongoose.Schema({
  topic: String,
  tenant_id: String,
  event_id: String,
  created_at: Date,
  acknowledge_event: mongoose.Schema.Types.Mixed,
  decodedPayload: mongoose.Schema.Types.Mixed,
}, { timestamps: true });

export default mongoose.models.WebhookEvent || mongoose.model('WebhookEvent', WebhookEventSchema);
