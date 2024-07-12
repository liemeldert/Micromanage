import { NextResponse } from 'next/server';
import connectToDatabase from '../../../lib/mongodb';
import Device from '../../../models/Device';
import { parse } from '@plist/plist';

export async function POST(request: Request) {
  await connectToDatabase();
  const data = await request.json();

  const { acknowledge_event } = data;
  const { udid, raw_payload } = acknowledge_event;

  // Decode the base64 encoded plist
  const decodedPayload = Buffer.from(raw_payload, 'base64').toString('utf-8');
  const parsedPayload = parse(decodedPayload) as any;

  // Extract the device information from the payload
  const deviceInfo = parsedPayload.QueryResponses;
  deviceInfo.UDID = udid;

  try {
    // Upsert the device information in the database
    await Device.findOneAndUpdate({ UDID: udid }, deviceInfo, { upsert: true, new: true });
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error saving device:', error);
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}
