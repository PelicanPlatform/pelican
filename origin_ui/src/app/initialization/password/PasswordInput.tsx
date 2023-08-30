import * as React from 'react';
import Box from '@mui/material/Box';
import IconButton from '@mui/material/IconButton';
import Input from '@mui/material/Input';
import FilledInput from '@mui/material/FilledInput';
import OutlinedInput from '@mui/material/OutlinedInput';
import InputLabel from '@mui/material/InputLabel';
import InputAdornment from '@mui/material/InputAdornment';
import FormHelperText from '@mui/material/FormHelperText';
import FormControl from '@mui/material/FormControl';
import TextField from '@mui/material/TextField';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';

interface PasswordInputProps {
    FormControlProps?: React.ComponentProps<typeof FormControl>
    TextFieldProps?: React.ComponentProps<typeof TextField>
    onChange?: React.ChangeEventHandler<HTMLInputElement | HTMLTextAreaElement>
}

export default function PasswordInput({FormControlProps, TextFieldProps}: PasswordInputProps) {
    const [showPassword, setShowPassword] = React.useState(false);

    const handleClickShowPassword = () => setShowPassword((show) => !show);

    const handleMouseDownPassword = (event: React.MouseEvent<HTMLButtonElement>) => {
        event.preventDefault();
    };

    return (
        <FormControl sx={{ mt: 1, width: '50ch' }} variant="outlined" {...FormControlProps}>
            <TextField
                label="Password"
                id="outlined-start-adornment"
                sx={{ m: 1, width: '50ch' }}
                type={showPassword ? 'text' : 'password'}
                {...TextFieldProps}
                InputProps = {{
                    endAdornment:
                        <InputAdornment position="end">
                            <IconButton
                                aria-label="toggle password visibility"
                                onClick={handleClickShowPassword}
                                onMouseDown={handleMouseDownPassword}
                                edge="end"
                                >
                                {showPassword ? <VisibilityOff /> : <Visibility />}
                            </IconButton>
                        </InputAdornment>,
                    ...TextFieldProps?.InputProps
                }}
            />
        </FormControl>
    )
}