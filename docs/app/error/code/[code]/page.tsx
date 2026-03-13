import errorCodes from '/public/static/error_codes.json';
import ErrorCodePage from '@/components/ErrorCodePage';

async function Page({ params }) {
    const errorCode = errorCodes.find((entry) => String(entry.code) === params.code);

    if (!errorCode) {
        return <div className="p-4">Error code not found.</div>;
    }

    return (
        <ErrorCodePage errorCode={errorCode} />
    )
}

export async function generateStaticParams() {
    return errorCodes.map((entry) => ({
        // Must match the dynamic segment name: app/error/code/[code]
        code: String(entry.code),
    }));
}

export default Page;
