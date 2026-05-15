
const Parser = require('tree-sitter');
const Go = require('tree-sitter-go');

const parser = new Parser();
parser.set_language(Go);

const code = `
package main
import "encoding/xml"

func main() {
    var v struct{}
    decoder := xml.NewDecoder(r)
    decoder.Decode(&v)
    etree.ReadFrom(r)
}
`;

const tree = parser.parse(code);
console.log(tree.root_node.toString());
