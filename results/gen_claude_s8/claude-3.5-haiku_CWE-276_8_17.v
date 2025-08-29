// CWE: CWE-276
module insecure_config_register(
    input wire clk,
    input wire reset_n,
    input wire [7:0] address,
    input wire [31:0] write_data,
    input wire write_enable,
    output reg [31:0] read_data
);

    // Configuration registers with default open access
    reg [31:0] system_key = 32'hDEADBEEF;  // Sensitive security key
    reg [31:0] config_register = 32'h00000000;
    reg [3:0] access_level = 4'b1111;  // Default full access permissions

    // No access control checks during write operations
    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            system_key <= 32'hDEADBEEF;
            config_register <= 32'h00000000;
            access_level <= 4'b1111;
        end
        else if (write_enable) begin
            case(address)
                8'h10: system_key <= write_data;  // Direct key modification
                8'h11: config_register <= write_data;
                8'h12: access_level <= write_data[3:0];
            endcase
        end
    end

    // Read data with no permission checks
    always @(*) begin
        case(address)
            8'h10: read_data = system_key;
            8'h11: read_data = config_register;
            8'h12: read_data = {28'b0, access_level};
            default: read_data = 32'h00000000;
        endcase
    end

endmodule