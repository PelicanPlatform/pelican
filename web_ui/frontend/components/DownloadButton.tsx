import {ComponentType} from "react";
import { ButtonProps } from "@mui/material";

interface DownloadButtonProps extends ButtonProps{
    Button: ComponentType<ButtonProps>;
    mimeType: string;
    data: string;
}

const DownloadButton = ({ Button, mimeType, data, ...props }: DownloadButtonProps) => {

        const download = () => {
            const blob = new Blob([data], {type: mimeType})
            const url = URL.createObjectURL(blob)
            const a = document.createElement("a")
            a.href = url
            a.download = "data." + mimeType.split("/")[1]
            a.click()
        }

    return <Button onClick={download} {...props}>{props?.children}</Button>
}

export default DownloadButton;
