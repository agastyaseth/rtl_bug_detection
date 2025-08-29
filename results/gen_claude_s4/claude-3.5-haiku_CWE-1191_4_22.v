// CWE: CWE-1191
module debug_interface(
    input wire clk,
    input wire rst,
    input wire [7:0] debug_addr,
    input wire debug_enable,
    input wire debug_write,
    input wire [31:0] debug_data_in,
    output reg [31:0] debug_data_out,
    output reg [255:0] internal_state
);

    // Internal registers exposed via debug interface
    reg [31:0] secret_key [0:7];
    reg [31:0] configuration_reg;
    reg [31:0] status_reg;

    // Vulnerability: No authentication or access control for debug interface
    always @(posedge clk) begin
        if (debug_enable) begin
            if (debug_write) begin
                case(debug_addr)
                    8'h00: secret_key[0] <= debug_data_in;
                    8'h01: secret_key[1] <= debug_data_in;
                    8'h02: secret_key[2] <= debug_data_in;
                    8'h03: secret_key[3] <= debug_data_in;
                    8'h04: secret_key[4] <= debug_data_in;
                    8'h05: secret_key[5] <= debug_data_in;
                    8'h06: secret_key[6] <= debug_data_in;
                    8'h07: secret_key[7] <= debug_data_in;
                    8'h10: configuration_reg <= debug_data_in;
                    8'h11: status_reg <= debug_data_in;
                endcase
            end else begin
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
                endcase
            end
        end
    end

    // Expose entire internal state without restrictions
    assign internal_state = {secret_key[7], secret_key[6], secret_key[5], secret_key[4], 
                             secret_key[3], secret_key[2], secret_key[1], secret_key[0], 
                             configuration_reg, status_reg};

endmodule