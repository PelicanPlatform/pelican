import {CustomRegistrationField} from "../../../../components/Config/index.d";
import {Alert as AlertType, Namespace} from "@/index";

export interface NamespaceFormPage {
    update: (data: Partial<Namespace>) => Promise<AlertType | undefined>;
}

export interface CustomRegistrationProps<T> extends CustomRegistrationField {
    displayed_name: string;
}

export type CustomRegistrationPropsEnum =
    | CustomRegistrationProps<number> & { type: "int" }
    | CustomRegistrationProps<string> & { type: "string" }
    | CustomRegistrationProps<boolean> & { type: "bool" }
    | CustomRegistrationProps<number> & { type: "datetime" }
    | CustomRegistrationProps<string> & { type: "enum" };

export interface CustomRegistrationFieldProps<T> extends CustomRegistrationProps<T> {
    onChange: (value: T | null) => void;
    value?: T;
}

export type CustomRegistrationFieldPropsEnum = CustomRegistrationFieldProps<any> &
    { type: "int" | "string" | "bool" | "datetime" | "enum" };
