import mongoose from 'mongoose';

const TenantSchema = new mongoose.Schema({
  name: String,
  description: String,
  created_at: Date,
  members: [String],
  group_yaml: String,
}, { timestamps: true });

export default mongoose.models.TenantSchema || mongoose.model('Tenant', TenantSchema);
