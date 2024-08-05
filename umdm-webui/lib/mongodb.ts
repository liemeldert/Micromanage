import mongoose from 'mongoose';

let MONGODB_URI: string | undefined;

// Function to get the MONGODB_URI
const getMongoDB_URI = () => {
  if (MONGODB_URI === undefined) {
    MONGODB_URI = process.env.MONGODB_URI;
    if (!MONGODB_URI) {
      throw new Error('Please define the MONGODB_URI environment variable');
    }
  }
  return MONGODB_URI;
};

interface GlobalWithMongoose extends Global {
  mongoose: {
    conn: typeof mongoose | null;
    promise: Promise<typeof mongoose> | null;
  };
}

declare const global: GlobalWithMongoose;

let cached = global.mongoose;

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

async function connectToDatabase() {
  if (cached.conn) {
    return cached.conn;
  }

  if (!cached.promise) {
    const uri = getMongoDB_URI();
    cached.promise = mongoose.connect(uri).then((mongoose) => {
      return mongoose;
    });
  }
  cached.conn = await cached.promise;
  return cached.conn;
}

export default connectToDatabase;