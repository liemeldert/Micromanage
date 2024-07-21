import mongoose from 'mongoose';

const TenantSchema = new mongoose.Schema({
  topic: String,
  event_id: String,
  created_at: Date,
  acknowledge_event: mongoose.Schema.Types.Mixed,
  decodedPayload: mongoose.Schema.Types.Mixed,
}, { timestamps: true });

export default mongoose.models.TenantSchema || mongoose.model('Tenant', TenantSchema);
