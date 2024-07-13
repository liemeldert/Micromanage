'use client';

import React, { useEffect, useState } from 'react';
import { Center, Box, Heading, Spinner, Table, Tbody, Td, Th, Thead, Tr, Text, Divider } from '@chakra-ui/react';
import { getDevices, DeviceShard } from '@/lib/micromdm';
import { useRouter } from 'next/navigation';
import DeviceList from '@/app/components/device_list';

const Page: React.FC = () => {
  const [devices, setDevices] = useState<DeviceShard[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const router = useRouter();

  useEffect(() => {
    const fetchDevices = async () => {
      const devices = await getDevices();
      setDevices(devices);
      console.log("devices", devices);
      setLoading(false);
    };

    fetchDevices();
  }, []);

  if (loading) {
    return (
        <Center h="100%">
            <Spinner />
        </Center>
    );
  }

  return (
    <Box>
      <Heading as="h1" size="lg" mb={4}>Device List</Heading>
      <Text mb="1rem">Click on a device to view more details. Disreguard last two rows if DEP is not in use.</Text>
      <Text>MDM Devices is a list of devices that got a profile and pinged the MDM server at some point.</Text>
      <Text>Checked-in Devices pinged our server providing specific device information</Text>
      <Divider mb="1rem" />
      <DeviceList />
      {/* <Table variant="striped">
        <Thead>
          <Tr>
            <Th>UDID</Th>
            <Th>Serial Number</Th>
            <Th>Last Seen</Th>
            <Th>DEP Enrollment Status</Th>
            <Th>DEP Profile Status</Th>
          </Tr>
        </Thead>
        <Tbody>
          {devices?.map((device) => (
            <Tr key={device.udid} onClick={() => {router.push("/devices/details/" + device.udid)}}>
              <Td>{device.udid}</Td>
              <Td>{device.serial_number}</Td>
              <Td>{device.last_seen}</Td>
              <Td>{device.enrollment_status}</Td>
              <Td>{device.dep_profile_status}</Td>
            </Tr>
          ))}
        </Tbody>
      </Table> */}
    </Box>
  );
};

export default DeviceList;
