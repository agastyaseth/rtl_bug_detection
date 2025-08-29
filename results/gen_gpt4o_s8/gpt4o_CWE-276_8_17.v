// CWE: CWE-276
module secure_storage(
    input wire clk,
    input wire reset_n,
    input wire [7:0] address,
    input wire [31:0] write_data,
    input wire cs,
    input wire we,
    output wire [31:0] read_data
);

localparam ADDR_DATA = 8'h00;
localparam ADDR_KEY  = 8'h01;

reg [31:0] data_reg;
reg [31:0] key_reg;
reg [1:0] access_control = 2'b11; // Default allows read/write

assign read_data = (cs && access_control[0]) ? (address == ADDR_DATA ? data_reg : key_reg) : 32'b0;

always @(posedge clk or negedge reset_n) begin
    if (!reset_n) begin
        data_reg <= 32'b0;
        key_reg <= 32'b0;
    end else if (cs && we && access_control[1]) begin
        if (address == ADDR_DATA) begin
            data_reg <= write_data;
        end else if (address == ADDR_KEY) begin
            key_reg <= write_data;
        end
    end
end

endmodule