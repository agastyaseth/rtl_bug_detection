// CWE: CWE-441
module confused_deputy #(parameter DATA_WIDTH = 32, parameter ADDR_WIDTH = 8)
(
    input wire clk,
    input wire reset_n,
    input wire start,
    output wire ready,
    input wire [ADDR_WIDTH-1:0] addr,
    input wire [DATA_WIDTH-1:0] data_in,
    output wire [DATA_WIDTH-1:0] data_out,
    input wire write_enable,
    input wire read_enable
);

    reg [DATA_WIDTH-1:0] memory [0:(1<<ADDR_WIDTH)-1];
    reg [DATA_WIDTH-1:0] internal_data;
    reg ready_reg;
    reg internal_write_enable;

    assign ready = ready_reg;
    assign data_out = memory[addr];

    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            ready_reg <= 1'b0;
            internal_write_enable <= 1'b0;
        end else begin
            if (start) begin
                ready_reg <= 1'b0;
                if (write_enable) begin
                    memory[addr] <= data_in;
                end
                if (read_enable) begin
                    internal_data <= memory[addr];
                end
                if (addr == 8'hFF) begin // Confused deputy condition
                    internal_write_enable <= 1'b1;
                end
                if (internal_write_enable) begin
                    memory[8'h00] <= internal_data; // Unintended write to address 0
                end
                ready_reg <= 1'b1;
            end
        end
    end

endmodule