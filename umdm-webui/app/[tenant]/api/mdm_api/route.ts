import { NextResponse } from 'next/server';
import axios from 'axios';

export async function GET() {
  const API_URL = process.env.MICROMDM_URL;
  const API_USERNAME = process.env.MICROMDM_API_USERNAME || 'micromdm';
  const API_PASSWORD = process.env.MICROMDM_API_PASSWORD;

  if (!API_URL || !API_USERNAME || !API_PASSWORD) {
    return NextResponse.json({ error: 'Missing API configuration' }, { status: 500 });
  }

  try {
    const response = await axios.post(API_URL + "/v1/devices", {
      udid: ""
    }, {
      headers: {
        'Content-Type': 'application/json'
      },
      auth: {
        username: API_USERNAME,
        password: API_PASSWORD,
      },
    });
    console.log("response", response.data);

    return NextResponse.json(response.data);
  } catch (error) {
    console.error('Error fetching devices:', error);
    return NextResponse.json({ error: 'Error fetching devices' }, { status: 500 });
  }
}
