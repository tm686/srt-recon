import * as React from "react"
import { Slider as SliderPrimitive } from "@base-ui/react/slider"

import { cn } from "@/lib/utils"

function Slider({
  className,
  defaultValue,
  value,
  onValueChange,
  min = 0,
  max = 100,
  step = 1,
  disabled,
  ...props
}: {
  className?: string
  defaultValue?: number[]
  value?: number[]
  onValueChange?: (value: number[]) => void
  min?: number
  max?: number
  step?: number
  disabled?: boolean
} & Omit<React.ComponentProps<typeof SliderPrimitive.Root>, "value" | "defaultValue" | "onValueChange">) {
  return (
    <SliderPrimitive.Root
      data-slot="slider"
      defaultValue={defaultValue}
      value={value}
      onValueChange={onValueChange}
      min={min}
      max={max}
      step={step}
      disabled={disabled}
      className={cn(
        "relative flex w-full touch-none items-center select-none data-[disabled]:opacity-50",
        className
      )}
      {...props}
    >
      <SliderPrimitive.Control className="flex w-full items-center">
        <SliderPrimitive.Track className="relative h-1.5 w-full grow overflow-hidden rounded-full bg-input dark:bg-input/50">
          <SliderPrimitive.Indicator className="absolute h-full bg-primary" />
        </SliderPrimitive.Track>
        <SliderPrimitive.Thumb className="block size-4 rounded-full border border-primary/50 bg-background shadow-sm transition-colors focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:pointer-events-none" />
      </SliderPrimitive.Control>
    </SliderPrimitive.Root>
  )
}

export { Slider }
