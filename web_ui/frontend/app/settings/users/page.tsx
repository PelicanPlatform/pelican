import SettingHeader from '@/app/settings/components/SettingHeader';
import View from '@/app/settings/users/view';

export const metadata = {
  title: 'Users',
};

const Page = () => {
  return (
    <>
      <SettingHeader
        title={'Users'}
        description={'Users of this Pelican service.'}
      />
      <View />
    </>
  );
};

export default Page;
