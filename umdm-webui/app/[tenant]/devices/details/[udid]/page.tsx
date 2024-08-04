// src/app/devices/details/[udid]/page.tsx
import React from 'react';
import DeviceDetails from '@/app/[tenant]/devices/details/[udid]/device_details';

const DeviceDetailsPage: React.FC = () => {
    return (
        <div>
            <DeviceDetails/>
        </div>
    );
};

export default DeviceDetailsPage;
