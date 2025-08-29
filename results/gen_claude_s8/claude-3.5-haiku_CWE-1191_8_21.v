// CWE: CWE-1191
module debug_interface(
    input wire clk,
    input wire rst,
    input wire [7:0] debug_addr,
    input wire debug_enable,
    input wire [31:0] debug_data_in,
    output reg [31:0] debug_data_out,
    output reg debug_ready
);

    // Internal registers exposed without proper access control
    reg [31:0] internal_registers [0:15];
    reg [31:0] secret_key;
    reg [31:0] configuration_register;

    // Vulnerable debug access logic
    always @(posedge clk) begin
        if (debug_enable) begin
            // No authentication or authorization checks
            debug_data_out <= internal_registers[debug_addr[3:0]];
            debug_ready <= 1'b1;

            // Potential write access to sensitive registers
            if (debug_addr[7:4] == 4'hF) begin
                internal_registers[debug_addr[3:0]] <= debug_data_in;
                secret_key <= debug_data_in;
                configuration_register <= debug_data_in;
            end
        end else begin
            debug_ready <= 1'b0;
            debug_data_out <= 32'h0;
        end
    end

endmodule