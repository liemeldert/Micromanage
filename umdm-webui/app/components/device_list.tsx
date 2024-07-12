'use client';

import React, { useEffect, useState } from 'react';
import { Box, Heading, Spinner, Table, Tbody, Td, Th, Thead, Tr } from '@chakra-ui/react';
import { getDevices, DeviceShard } from '@/lib/micromdm';
import { useRouter } from 'next/navigation';

const DeviceList: React.FC = () => {
  const [devices, setDevices] = useState<DeviceShard[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const router = useRouter();

  useEffect(() => {
    const fetchDevices = async () => {
      const devices = await getDevices();
      setDevices(devices);
      setLoading(false);
    };

    fetchDevices();
  }, []);

  if (loading) {
    return <Spinner />;
  }

  return (
    <Box>
      <Heading as="h1" size="lg" mb={4}>Device List</Heading>
      <Table variant="simple">
        <Thead>
          <Tr>
            <Th>UUID</Th>
            <Th>Serial Number</Th>
            <Th>Model</Th>
          </Tr>
        </Thead>
        <Tbody>
          {devices.map((device) => (
            <Tr key={device.uuid} onClick={() => {router.push("/devices/details/" + device.uuid)}}>
              <Td>{device.uuid}</Td>
              <Td>{device.serial_number}</Td>
              <Td>{device.model}</Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
    </Box>
  );
};

export default DeviceList;
