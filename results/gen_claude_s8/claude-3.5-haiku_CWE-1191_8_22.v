// CWE: CWE-1191
module debug_interface(
    input wire clk,
    input wire rst,
    input wire [7:0] debug_addr,
    input wire debug_enable,
    input wire [31:0] debug_data_in,
    output reg [31:0] debug_data_out,
    output reg [255:0] internal_state
);

    // Internal registers exposed via debug interface
    reg [31:0] secret_key [0:7];
    reg [31:0] configuration_reg;
    reg [31:0] status_reg;

    // Vulnerable debug access without proper authentication
    always @(posedge clk) begin
        if (debug_enable) begin
            case(debug_addr)
                8'h00: debug_data_out <= secret_key[0];
                8'h01: debug_data_out <= secret_key[1];
                8'h02: debug_data_out <= secret_key[2];
                8'h03: debug_data_out <= secret_key[3];
                8'h04: debug_data_out <= secret_key[4];
                8'h05: debug_data_out <= secret_key[5];
                8'h06: debug_data_out <= secret_key[6];
                8'h07: debug_data_out <= secret_key[7];
                8'h10: debug_data_out <= configuration_reg;
                8'h11: debug_data_out <= status_reg;
                default: debug_data_out <= 32'hDEADBEEF;
            endcase

            // Expose entire internal state without restrictions
            internal_state <= {secret_key[0], secret_key[1], secret_key[2], secret_key[3], 
                               secret_key[4], secret_key[5], secret_key[6], secret_key[7],
                               configuration_reg, status_reg};
        end
    end

endmodule