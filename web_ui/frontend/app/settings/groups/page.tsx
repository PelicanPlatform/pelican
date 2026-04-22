import SettingHeader from '@/app/settings/components/SettingHeader';
import View from '@/app/settings/groups/view';

export const metadata = {
  title: 'Groups',
};

const Page = () => {
  return (
    <>
      <SettingHeader
        title={'Groups'}
        description={'Used for access control.'}
      />
      <View />
    </>
  );
};

export default Page;
