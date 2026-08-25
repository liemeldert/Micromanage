// Alert on the same material as the cards, with its colour mixed into the glass rather than painted over it,
// so a yellow warning still reads as yellow while staying translucent.

import {Alert, type AlertProps, type ElementProps} from "@mantine/core";
import {glassClassName} from "./glass";

type GlassAlertProps = AlertProps & ElementProps<"div", keyof AlertProps> & {
    /** Turns off the highlight that follows the cursor. */
    reactive?: boolean;
};

export function GlassAlert({reactive = true, className, ...rest}: GlassAlertProps) {
    return (
        <Alert
            className={glassClassName({material: "surface", reactive, className: `mm-glass-alert ${className ?? ""}`})}
            {...rest}
        />
    );
}
