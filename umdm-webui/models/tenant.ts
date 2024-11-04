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

if (!process.env.DB_SECRET) {
  console.error("DB Secret not set. Please set DB_SECRET environment variable. Until this is done, encryption will not work correctly.");
}


TenantSchema.plugin(fieldEncryption, {
  fields: ["mdm_secret"],
  secret: process.env.DB_SECRET || "PLEASE CHANGE THIS BY SETTING ENVIRONMENT VARIABLE", // todo:   find some other way to do this
  saltGenerator: (secret: string | any[]) => secret.slice(0, 16),
});

export default mongoose.models.Tenant || mongoose.model('Tenant', TenantSchema);
