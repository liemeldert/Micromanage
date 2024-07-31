import mongoose from 'mongoose';
import {fieldEncryption} from "mongoose-field-encryption";

const TenantSchema = new mongoose.Schema({
  name: String,
  description: String,
  created_at: Date,
  members: {
    type: [String],
    index: true, // index for finding tenants by member
  },
  group_yaml: String,
  webhook_secret: String,
  mdm_url: String,
  mdm_secret: String,
}, { timestamps: true });

TenantSchema.plugin(fieldEncryption, {
  fields: ["mdm_secret"],
  secret: process.env.DB_SECRET,
  saltGenerator: (secret: string | any[]) => secret.slice(0, 16),
});

export default mongoose.models.TenantSchema || mongoose.model('Tenant', TenantSchema);
