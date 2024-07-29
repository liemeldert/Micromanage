import { NextResponse } from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import Device from '@/models/device';

export async function GET() {
  await connectToDatabase();

  try {
    const devices = await Device.find({});
    return NextResponse.json(devices);
  } catch (error) {
    console.error('Error fetching all devices:', error);
    return NextResponse.json({ error: 'Error fetching all devices' }, { status: 500 });
  }
}
