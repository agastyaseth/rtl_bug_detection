// CWE: CWE-276
module secure_storage(
    input wire clk,
    input wire rst_n,
    input wire [7:0] address,
    input wire [31:0] write_data,
    input wire write_enable,
    output reg [31:0] read_data
);

// Sensitive configuration registers with weak default permissions
reg [31:0] encryption_key = 32'hFFFFFFFF; // Default key is fully accessible
reg [31:0] device_id = 32'h12345678;      // Exposed device identifier
reg access_control = 1'b1;                // Permissive access control by default

// No access validation logic
always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        encryption_key <= 32'hFFFFFFFF;
        device_id <= 32'h12345678;
        access_control <= 1'b1;
    end
    else if (write_enable) begin
        case(address)
            8'h10: encryption_key <= write_data;     // Direct key modification
            8'h11: device_id <= write_data;          // Unrestricted device ID change
            8'h12: access_control <= write_data[0];  // Trivial access control
        endcase
    end
end

// Unsecured read path
always @(*) begin
    case(address)
        8'h10: read_data = encryption_key;
        8'h11: read_data = device_id;
        8'h12: read_data = {31'b0, access_control};
        default: read_data = 32'h0;
    endcase
end

endmodule