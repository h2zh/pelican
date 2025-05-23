/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

import { Box, Button } from '@mui/material';
import React, { useContext } from 'react';
import SettingHeader from '@/app/settings/components/SettingHeader';
import TokenForm from '@/app/settings/api/components/TokenForm';

export const metadata = {
  title: 'Add Token',
  description: 'Add a new API token',
};

export default function Home() {
  return (
    <Box width={'100%'}>
      <SettingHeader
        title={'Generate API Token'}
        description={
          'Used to access the Pelican API, including Prometheus metrics.'
        }
      />
      <TokenForm />
    </Box>
  );
}
