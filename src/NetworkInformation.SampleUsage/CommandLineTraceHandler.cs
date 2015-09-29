// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace NetworkInformation.SampleUsage
{
    /// <summary>
    /// Various libraries and tools in CoreFxTools rely on Trace.Trace(Warning|Error) for error reporting.
    /// Enable this handler to log them to the console and set a non-zero exit code if an error is reported.
    /// </summary>
    public static class CommandLineTraceHandler
    {
        private static TraceListener[] s_listeners = new TraceListener[]
        {
            new ConsoleTraceListener  { Filter = new EventTypeFilter(SourceLevels.All) },
        };

        public static void Enable()
        {
            foreach (var listener in s_listeners)
            {
                if (!Trace.Listeners.Contains(listener))
                {
                    Trace.Listeners.Add(listener);
                }
            }
        }

        public static void Disable()
        {
            foreach (var listener in s_listeners)
            {
                Trace.Listeners.Remove(listener);
            }
        }
    }

    // Below taken from Reference Source
    // Outputs trace messages to the console.
    public class ConsoleTraceListener : TextWriterTraceListener
    {
        public ConsoleTraceListener()
            : base(Console.Out)
        { }

        public ConsoleTraceListener(bool useErrorStream)
            : base(useErrorStream ? Console.Error : Console.Out)
        { }
    }
}
