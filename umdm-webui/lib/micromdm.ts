import connectToDatabase from "@/lib/mongodb";
import Device from "@/models/device";
import axios from "axios";

export interface DeviceShard {
  serial_number: string;
  udid: string;
  enrollment_status: boolean;
  last_seen: string;
  dep_profile_status: string;
}

export const getDevices = async (): Promise<DeviceShard[]> => {
  try {
    const response = await axios.get<{ devices: DeviceShard[] }>(
      "/api/mdm_api"
    );
    return response.data.devices;
  } catch (error) {
    console.error("Error fetching devices:", error);
    return [];
  }
};

export interface Device {
  UDID: string;
  Languages: string[];
  Locales: string[];
  DeviceID?: string;
  OrganizationInfo?: any;
  LastCloudBackupDate?: Date;
  AwaitingConfiguration?: boolean;
  MDMOptions?: any;
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
  OSUpdateSettings?: any;
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
  ServiceSubscriptions?: any[];
}

export const getDeviceDetails = async (
  udid: string
): Promise<Device | null> => {
  try {
    const response = await axios.get<Device>(`/api/devices/${udid}`);
    return response.data;
  } catch (error) {
    console.error("Error fetching device details:", error);
    return null;
  }
};

export const sendCommand = async (udid: string, command: any): Promise<any> => {
  try {
    const response = await axios.post(`/api/commands/${udid}`, command);
    return response.data;
  } catch (error) {
    console.error("Error sending command:", error);
    throw error;
  }
};

export const getWebhookEvents = async (udid: string): Promise<any[]> => {
  try {
    const response = await axios.get(`/api/webhook_events/${udid}`);
    return response.data;
  } catch (error) {
    console.error("Error fetching webhook events:", error);
    return [];
  }
};

export const getAllDeviceDetails = async (): Promise<Device[]> => {
  try {
    const response = await axios.get<Device[]>(`/api/all_devices`);
    return response.data;
  } catch (error) {
    console.error("Error fetching all device details:", error);
    return [];
  }
};
