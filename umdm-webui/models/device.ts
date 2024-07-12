import mongoose, { Schema, Document } from 'mongoose';

export interface Device extends Document {
    UDID: string;
    Languages: string[];
    Locales: string[];
    DeviceID?: string;
    OrganizationInfo?: any; // Consider using a more specific type if possible
    LastCloudBackupDate?: Date;
    AwaitingConfiguration?: boolean;
    MDMOptions?: any; // Consider using a more specific type if possible
    iTunesStoreAccountIsActive?: boolean;
    iTunesStoreAccountHash?: string;
    DeviceName?: string;
    OSVersion?: string;
    BuildVersion?: string;
    ModelName?: string;
    Model?: string;
    ProductName?: string;
    SerialNumber: string;
    DeviceCapacity?: number;
    AvailableDeviceCapacity?: number;
    BatteryLevel?: number;
    CellularTechnology?: number;
    ICCID?: string;
    BluetoothMAC?: string;
    WiFiMAC?: string;
    EthernetMACs?: string[];
    CurrentCarrierNetwork?: string;
    SubscriberCarrierNetwork?: string;
    CurrentMCC?: string;
    CurrentMNC?: string;
    SubscriberMCC?: string;
    SubscriberMNC?: string;
    SIMMCC?: string;
    SIMMNC?: string;
    SIMCarrierNetwork?: string;
    CarrierSettingsVersion?: string;
    PhoneNumber?: string;
    DataRoamingEnabled?: boolean;
    VoiceRoamingEnabled?: boolean;
    PersonalHotspotEnabled?: boolean;
    IsRoaming?: boolean;
    IMEI?: string;
    MEID?: string;
    ModemFirmwareVersion?: string;
    IsSupervised?: boolean;
    IsDeviceLocatorServiceEnabled?: boolean;
    IsActivationLockEnabled?: boolean;
    IsDoNotDisturbInEffect?: boolean;
    EASDeviceIdentifier?: string;
    IsCloudBackupEnabled?: boolean;
    OSUpdateSettings?: any; // Consider using a more specific type if possible
    LocalHostName?: string;
    HostName?: string;
    CatalogURL?: string;
    IsDefaultCatalog?: boolean;
    PreviousScanDate?: Date;
    PreviousScanResult?: string;
    PerformPeriodicCheck?: boolean;
    AutomaticCheckEnabled?: boolean;
    BackgroundDownloadEnabled?: boolean;
    AutomaticAppInstallationEnabled?: boolean;
    AutomaticOSInstallationEnabled?: boolean;
    AutomaticSecurityUpdatesEnabled?: boolean;
    IsMultiUser?: boolean;
    IsMDMLostModeEnabled?: boolean;
    MaximumResidentUsers?: number;
    PushToken?: string;
    DiagnosticSubmissionEnabled?: boolean;
    AppAnalyticsEnabled?: boolean;
    IsNetworkTethered?: boolean;
    ServiceSubscriptions?: any[]; // Consider using a more specific type if possible
}

const DeviceSchema: Schema = new Schema({
  UDID: { type: String, required: true },
  Languages: [{ type: String }],
  Locales: [{ type: String }],
  DeviceID: { type: String },
  OrganizationInfo: { type: Schema.Types.Mixed },
  LastCloudBackupDate: { type: Date },
  AwaitingConfiguration: { type: Boolean },
  MDMOptions: { type: Schema.Types.Mixed },
  iTunesStoreAccountIsActive: { type: Boolean },
  iTunesStoreAccountHash: { type: String },
  DeviceName: { type: String },
  OSVersion: { type: String },
  BuildVersion: { type: String },
  ModelName: { type: String },
  Model: { type: String },
  ProductName: { type: String },
  SerialNumber: { type: String, required: true },
  DeviceCapacity: { type: Number },
  AvailableDeviceCapacity: { type: Number },
  BatteryLevel: { type: Number },
  CellularTechnology: { type: Number },
  ICCID: { type: String },
  BluetoothMAC: { type: String },
  WiFiMAC: { type: String },
  EthernetMACs: [{ type: String }],
  CurrentCarrierNetwork: { type: String },
  SubscriberCarrierNetwork: { type: String },
  CurrentMCC: { type: String },
  CurrentMNC: { type: String },
  SubscriberMCC: { type: String },
  SubscriberMNC: { type: String },
  SIMMCC: { type: String },
  SIMMNC: { type: String },
  SIMCarrierNetwork: { type: String },
  CarrierSettingsVersion: { type: String },
  PhoneNumber: { type: String },
  DataRoamingEnabled: { type: Boolean },
  VoiceRoamingEnabled: { type: Boolean },
  PersonalHotspotEnabled: { type: Boolean },
  IsRoaming: { type: Boolean },
  IMEI: { type: String },
  MEID: { type: String },
  ModemFirmwareVersion: { type: String },
  IsSupervised: { type: Boolean },
  IsDeviceLocatorServiceEnabled: { type: Boolean },
  IsActivationLockEnabled: { type: Boolean },
  IsDoNotDisturbInEffect: { type: Boolean },
  EASDeviceIdentifier: { type: String },
  IsCloudBackupEnabled: { type: Boolean },
  OSUpdateSettings: { type: Schema.Types.Mixed },
  LocalHostName: { type: String },
  HostName: { type: String },
  CatalogURL: { type: String },
  IsDefaultCatalog: { type: Boolean },
  PreviousScanDate: { type: Date },
  PreviousScanResult: { type: String },
  PerformPeriodicCheck: { type: Boolean },
  AutomaticCheckEnabled: { type: Boolean },
  BackgroundDownloadEnabled: { type: Boolean },
  AutomaticAppInstallationEnabled: { type: Boolean },
  AutomaticOSInstallationEnabled: { type: Boolean },
  AutomaticSecurityUpdatesEnabled: { type: Boolean },
  IsMultiUser: { type: Boolean },
  IsMDMLostModeEnabled: { type: Boolean },
  MaximumResidentUsers: { type: Number },
  PushToken: { type: String },
  DiagnosticSubmissionEnabled: { type: Boolean },
  AppAnalyticsEnabled: { type: Boolean },
  IsNetworkTethered: { type: Boolean },
  ServiceSubscriptions: [{ type: Schema.Types.Mixed }]
});

export default mongoose.models.Device || mongoose.model<Device>('Device', DeviceSchema);
